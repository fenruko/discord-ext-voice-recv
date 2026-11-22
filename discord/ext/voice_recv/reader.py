from __future__ import annotations

import time
import logging
import threading
import sys

from operator import itemgetter
from typing import TYPE_CHECKING

from . import rtp
from .sinks import AudioSink
from .router import PacketRouter, SinkEventRouter

try:
    import nacl.secret
    from nacl.exceptions import CryptoError
except ImportError as e:
    raise RuntimeError("pynacl is required") from e

if TYPE_CHECKING:
    from typing import Optional, Callable, Any, Dict, Literal, Union

    from discord import Member
    from discord.types.voice import SupportedModes
    from .voice_client import VoiceRecvClient
    from .rtp import RTPPacket

    DecryptRTP = Callable[[RTPPacket], bytes]
    DecryptRTCP = Callable[[bytes], bytes]
    AfterCB = Callable[[Optional[Exception]], Any]
    SpeakingEvent = Literal['voice_member_speaking_start', 'voice_member_speaking_stop']

log = logging.getLogger(__name__)

__all__ = [
    'AudioReader',
]

class AudioReader:
    def __init__(self, sink: AudioSink, voice_client: VoiceRecvClient, *, after: Optional[AfterCB] = None):
        if after is not None and not callable(after):
            raise TypeError('Expected a callable for the "after" parameter.')

        self.sink: AudioSink = sink
        self.voice_client: VoiceRecvClient = voice_client
        self.after: Optional[AfterCB] = after

        self.sink._voice_client = voice_client

        self.active: bool = False
        self.error: Optional[Exception] = None
        self.packet_router: PacketRouter = PacketRouter(sink, self)
        self.event_router: SinkEventRouter = SinkEventRouter(sink, self)
        self.decryptor: PacketDecryptor = PacketDecryptor(voice_client.mode, bytes(voice_client.secret_key))
        self.speaking_timer: SpeakingTimer = SpeakingTimer(self)
        self.keepalive: UDPKeepAlive = UDPKeepAlive(voice_client)

    def is_listening(self) -> bool:
        return self.active

    def update_secret_key(self, secret_key: bytes) -> None:
        self.decryptor.update_secret_key(secret_key)

    def start(self) -> None:
        if self.active:
            return

        self.speaking_timer.start()
        self.event_router.start()
        self.packet_router.start()
        self.voice_client._connection.add_socket_listener(self.callback)
        self.keepalive.start()
        self.active = True

    def stop(self) -> None:
        if not self.active:
            return

        self.voice_client._connection.remove_socket_listener(self.callback)
        self.active = False
        self.speaking_timer.notify()

        threading.Thread(target=self._stop, name=f'audioreader-stopper-{id(self):x}').start()

    def _stop(self) -> None:
        try:
            self.packet_router.stop()
        except Exception as e:
            self.error = e

        try:
            self.event_router.stop()
        except Exception as e:
            self.error = e

        self.speaking_timer.stop()
        self.keepalive.stop()

        if self.after:
            try:
                self.after(self.error)
            except Exception:
                pass

        for sink in self.sink.root.walk_children(with_self=True):
            try:
                sink.cleanup()
            except Exception:
                pass

    def set_sink(self, sink: AudioSink) -> AudioSink:
        old_sink = self.sink
        old_sink._voice_client = None
        sink._voice_client = self.voice_client
        self.packet_router.set_sink(sink)
        self.sink = sink
        return old_sink

    def _is_ip_discovery_packet(self, data: bytes) -> bool:
        return len(data) == 74 and data[1] == 0x02

    def callback(self, packet_data: bytes) -> None:
        packet = rtp_packet = rtcp_packet = None
        try:
            if not rtp.is_rtcp(packet_data):
                packet = rtp_packet = rtp.decode_rtp(packet_data)
                
                decrypted_transport = bytes(self.decryptor.decrypt_rtp(packet))
                
                vc = self.voice_client
                session = None
                
                targets = [vc, getattr(vc, 'ws', None), getattr(vc, '_connection', None)]
                for target in targets:
                    if target is None:
                        continue
                    for attr in dir(target):
                        if 'dave' in attr.lower():
                            val = getattr(target, attr)
                            if isinstance(val, type):
                                continue
                            if hasattr(val, 'decrypt') or hasattr(val, 'decrypt_audio'):
                                session = val
                                break
                            if hasattr(val, '_session') and (hasattr(val._session, 'decrypt') or hasattr(val._session, 'decrypt_audio')):
                                session = val._session
                                break
                    if session is not None:
                        break

                conn = getattr(vc, '_connection', None)
                if session is None or getattr(conn, 'dave_protocol_version', None) == 0:
                    # No DAVE E2EE on this connection (or in this channel): the
                    # transport-decrypted payload is already plain Opus.
                    packet.decrypted_data = decrypted_transport
                else:
                    user_id = self.voice_client._ssrc_to_id.get(packet.ssrc)
                    
                    if user_id is None:
                        ws = getattr(self.voice_client, 'ws', None)
                        if ws and hasattr(ws, 'ssrc_map'):
                            user_id = ws.ssrc_map.get(packet.ssrc)
                        elif ws and hasattr(ws, '_ssrc_map'):
                            user_id = ws._ssrc_map.get(packet.ssrc)

                    if user_id is None:
                        if not hasattr(self, '_logged_unknown_ssrcs'):
                            self._logged_unknown_ssrcs = set()
                        if packet.ssrc not in self._logged_unknown_ssrcs:
                            log.warning(f"[DAVE] Dropping packet for SSRC {packet.ssrc}: Could not find matching User ID.")
                            self._logged_unknown_ssrcs.add(packet.ssrc)
                        return
                    
                    uid_int = int(user_id)
                    media_type = 1
                    
                    davey = sys.modules.get('davey')
                    if davey and hasattr(davey, 'MediaType'):
                        media_type = getattr(davey.MediaType, 'audio', media_type)
                        
                    try:
                        res = session.decrypt(uid_int, media_type, decrypted_transport)
                        packet.decrypted_data = res if isinstance(res, bytes) else res[0]
                    except Exception as e1:
                        try:
                            res = session.decrypt(media_type, uid_int, decrypted_transport)
                            packet.decrypted_data = res if isinstance(res, bytes) else res[0]
                        except Exception as e2:
                            if not hasattr(self, '_logged_decrypt_errors'):
                                self._logged_decrypt_errors = set()
                            if user_id not in self._logged_decrypt_errors:
                                try:
                                    known = list(session.get_user_ids())
                                except Exception as ge:
                                    known = f"unavailable ({ge})"
                                log.error(
                                    f"[DAVE] Decrypt failed for User {uid_int}: {e1} | {e2} "
                                    f"[ready={getattr(session, 'ready', '?')} "
                                    f"protocol={getattr(conn, 'dave_protocol_version', '?')} "
                                    f"user_in_group={uid_int in known if isinstance(known, list) else '?'} "
                                    f"group_members={known}]"
                                )
                                self._logged_decrypt_errors.add(user_id)
                            return

            else:
                decrypted_rtcp = self.decryptor.decrypt_rtcp(packet_data)
                packet = rtcp_packet = rtp.decode_rtcp(decrypted_rtcp)
                
        except Exception as e:
            return
        finally:
            if self.error:
                self.stop()
                return
            if not packet:
                return

        if rtcp_packet:
            self.packet_router.feed_rtcp(rtcp_packet)
        elif rtp_packet:
            ssrc = rtp_packet.ssrc

            self.speaking_timer.notify(ssrc)
            try:
                self.packet_router.feed_rtp(rtp_packet)
            except Exception as e:
                self.error = e
                self.stop()

class PacketDecryptor:
    supported_modes: list[str] = [
        'aead_aes256_gcm_rtpsize',
        'aead_aes256_gcm',
        'aead_xchacha20_poly1305_rtpsize',
        'xsalsa20_poly1305_lite',
        'xsalsa20_poly1305_suffix',
        'xsalsa20_poly1305',
    ]

    def __init__(self, mode: str, secret_key: bytes) -> None:
        self.mode: str = mode
        try:
            self.decrypt_rtp: DecryptRTP = getattr(self, '_decrypt_rtp_' + mode)
            self.decrypt_rtcp: DecryptRTCP = getattr(self, '_decrypt_rtcp_' + mode)
        except AttributeError as e:
            raise NotImplementedError(mode) from e

        self.box: Any = self._make_box(secret_key)

    def _make_box(self, secret_key: bytes) -> Any:
        if self.mode.startswith("aead_aes256_gcm"):
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            return AESGCM(secret_key)
        elif self.mode.startswith("aead"):
            return nacl.secret.Aead(secret_key)
        else:
            return nacl.secret.SecretBox(secret_key)

    def update_secret_key(self, secret_key: bytes) -> None:
        self.box = self._make_box(secret_key)

    def _decrypt_rtp_aead_aes256_gcm_rtpsize(self, packet: RTPPacket) -> bytes:
        packet.adjust_rtpsize()
        nonce = bytearray(12)
        nonce[:4] = packet.nonce
        result = self.box.decrypt(bytes(nonce), bytes(packet.data), bytes(packet.header))
        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]
        return result

    def _decrypt_rtcp_aead_aes256_gcm_rtpsize(self, data: bytes) -> bytes:
        nonce = bytearray(12)
        nonce[:4] = data[-4:]
        header = data[:8]
        result = self.box.decrypt(bytes(nonce), data[8:-4], bytes(header))
        return header + result

    def _decrypt_rtp_aead_aes256_gcm(self, packet: RTPPacket) -> bytes:
        nonce = bytearray(12)
        nonce[:12] = packet.header
        result = self.box.decrypt(bytes(nonce), bytes(packet.data), bytes(packet.header))
        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]
        return result

    def _decrypt_rtcp_aead_aes256_gcm(self, data: bytes) -> bytes:
        nonce = bytearray(12)
        nonce[:8] = data[:8]
        header = data[:8]
        result = self.box.decrypt(bytes(nonce), data[8:], bytes(header))
        return header + result

    def _decrypt_rtp_xsalsa20_poly1305(self, packet: RTPPacket) -> bytes:
        nonce = bytearray(24)
        nonce[:12] = packet.header
        result = self.box.decrypt(bytes(packet.data), bytes(nonce))
        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]
        return result

    def _decrypt_rtcp_xsalsa20_poly1305(self, data: bytes) -> bytes:
        nonce = bytearray(24)
        nonce[:8] = data[:8]
        result = self.box.decrypt(data[8:], bytes(nonce))
        return data[:8] + result

    def _decrypt_rtp_xsalsa20_poly1305_suffix(self, packet: RTPPacket) -> bytes:
        nonce = packet.data[-24:]
        voice_data = packet.data[:-24]
        result = self.box.decrypt(bytes(voice_data), bytes(nonce))
        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]
        return result

    def _decrypt_rtcp_xsalsa20_poly1305_suffix(self, data: bytes) -> bytes:
        nonce = data[-24:]
        header = data[:8]
        result = self.box.decrypt(data[8:-24], nonce)
        return header + result

    def _decrypt_rtp_xsalsa20_poly1305_lite(self, packet: RTPPacket) -> bytes:
        nonce = bytearray(24)
        nonce[:4] = packet.data[-4:]
        voice_data = packet.data[:-4]
        result = self.box.decrypt(bytes(voice_data), bytes(nonce))
        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]
        return result

    def _decrypt_rtcp_xsalsa20_poly1305_lite(self, data: bytes) -> bytes:
        nonce = bytearray(24)
        nonce[:4] = data[-4:]
        header = data[:8]
        result = self.box.decrypt(data[8:-4], bytes(nonce))
        return header + result

    def _decrypt_rtp_aead_xchacha20_poly1305_rtpsize(self, packet: RTPPacket) -> bytes:
        packet.adjust_rtpsize()
        nonce = bytearray(24)
        nonce[:4] = packet.nonce
        voice_data = packet.data
        result = self.box.decrypt(bytes(voice_data), bytes(packet.header), bytes(nonce))
        if packet.extended:
            offset = packet.update_ext_headers(result)
            result = result[offset:]
        return result

    def _decrypt_rtcp_aead_xchacha20_poly1305_rtpsize(self, data: bytes) -> bytes:
        nonce = bytearray(24)
        nonce[:4] = data[-4:]
        header = data[:8]
        result = self.box.decrypt(data[8:-4], bytes(header), bytes(nonce))
        return header + result

class SpeakingTimer(threading.Thread):
    def __init__(self, reader: AudioReader):
        super().__init__(daemon=True, name=f'speaking-timer-{id(self):x}')
        self.reader: AudioReader = reader
        self.voice_client = reader.voice_client
        self.speaking_timeout_delay: float = 0.2
        self.last_speaking_state: Dict[int, bool] = {}
        self.speaking_cache: Dict[int, float] = {}
        self.speaking_timer_event: threading.Event = threading.Event()
        self._end_thread: threading.Event = threading.Event()

    def _lookup_member(self, ssrc: int) -> Optional[Member]:
        whoid = self.voice_client._get_id_from_ssrc(ssrc)
        return self.voice_client.guild.get_member(whoid) if whoid else None

    def maybe_dispatch_speaking_start(self, ssrc: int) -> None:
        tlast = self.speaking_cache.get(ssrc)
        if tlast is None or tlast + self.speaking_timeout_delay < time.perf_counter():
            self.dispatch('voice_member_speaking_start', ssrc)

    def dispatch(self, event: SpeakingEvent, ssrc: int) -> None:
        who = self._lookup_member(ssrc)
        if not who:
            return
        self.voice_client.dispatch_sink(event, who)

    def notify(self, ssrc: Optional[int] = None) -> None:
        if ssrc is not None:
            self.last_speaking_state[ssrc] = True
            self.maybe_dispatch_speaking_start(ssrc)
            self.speaking_cache[ssrc] = time.perf_counter()
        self.speaking_timer_event.set()
        self.speaking_timer_event.clear()

    def drop_ssrc(self, ssrc: int) -> None:
        self.speaking_cache.pop(ssrc, None)
        state = self.last_speaking_state.pop(ssrc, None)
        if state:
            self.dispatch('voice_member_speaking_stop', ssrc)
        self.notify()

    def get_speaking(self, ssrc: int) -> Optional[bool]:
        return self.last_speaking_state.get(ssrc)

    def stop(self) -> None:
        self._end_thread.set()
        self.notify()

    def run(self) -> None:
        _i1 = itemgetter(1)
        def get_next_entry():
            cache = sorted(self.speaking_cache.items(), key=_i1)
            for ssrc, tlast in cache:
                if self.last_speaking_state.get(ssrc):
                    return ssrc, tlast
            return None, None

        self.speaking_timer_event.wait()
        while not self._end_thread.is_set():
            if not self.speaking_cache:
                self.speaking_timer_event.wait()
            tnow = time.perf_counter()
            ssrc, tlast = get_next_entry()
            if ssrc is None or tlast is None:
                self.speaking_timer_event.wait()
                continue
            self.speaking_timer_event.wait(tlast + self.speaking_timeout_delay - tnow)
            if time.perf_counter() < tlast + self.speaking_timeout_delay:
                continue
            self.dispatch('voice_member_speaking_stop', ssrc)
            self.last_speaking_state[ssrc] = False

class UDPKeepAlive(threading.Thread):
    delay: int = 5000

    def __init__(self, voice_client: VoiceRecvClient):
        super().__init__(daemon=True, name=f"voice-udp-keepalive-{id(self):x}")
        self.voice_client: VoiceRecvClient = voice_client
        self.last_time: float = 0
        self.counter: int = 0
        self._end_thread: threading.Event = threading.Event()

    def run(self) -> None:
        self.voice_client.wait_until_connected()
        while not self._end_thread.is_set():
            vc = self.voice_client
            try:
                packet = self.counter.to_bytes(8, 'big')
            except OverflowError:
                self.counter = 0
                continue
            try:
                vc._connection.socket.sendto(packet, (vc._connection.endpoint_ip, vc._connection.voice_port))
            except Exception:
                vc.wait_until_connected()
                if vc.is_connected():
                    continue
                break
            else:
                self.counter += 1
                time.sleep(self.delay)

    def stop(self) -> None:
        self._end_thread.set()
