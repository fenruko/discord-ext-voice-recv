from __future__ import annotations

import time
import logging
import threading

from operator import itemgetter
from typing import TYPE_CHECKING

import davey

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
        self._waiting_for_dave: bool = False
        self._logged_unknown_ssrcs: set[int] = set()
        self._logged_decrypt_errors: set[int] = set()

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

    def _decrypt_dave(self, packet: RTPPacket, data: bytes) -> Optional[bytes]:
        connection = self.voice_client._connection
        protocol_version = getattr(connection, 'dave_protocol_version', 0)
        if protocol_version == 0:
            # Older discord.py versions and non-DAVE channels use plain Opus
            # after transport decryption.
            self._waiting_for_dave = False
            return data

        session = getattr(connection, 'dave_session', None)
        if session is None or not session.ready:
            # Group membership alone does not mean the media keys are installed.
            # Never pass encrypted data to the Opus decoder while waiting for them.
            if not self._waiting_for_dave:
                log.warning(
                    "[DAVE] Dropping audio while waiting for session keys [protocol=%s davey=%s]. "
                    "If this persists, check discord.py/davey version compatibility.",
                    protocol_version,
                    davey.__version__,
                )
                self._waiting_for_dave = True
            return None
        self._waiting_for_dave = False

        user_id = self.voice_client._ssrc_to_id.get(packet.ssrc)
        if user_id is None:
            if packet.ssrc not in self._logged_unknown_ssrcs:
                log.warning("[DAVE] Dropping packet for SSRC %s: Could not find matching User ID.", packet.ssrc)
                self._logged_unknown_ssrcs.add(packet.ssrc)
            return None
        self._logged_unknown_ssrcs.discard(packet.ssrc)
        user_id = int(user_id)

        try:
            # A decryption failure is not evidence of a different API signature:
            # davey expects the user ID first, then the media type and payload.
            result = session.decrypt(user_id, davey.MediaType.audio, data)
        except Exception as exc:
            if user_id not in self._logged_decrypt_errors:
                known: Union[list[int], str]
                try:
                    # davey 0.1.x returns string IDs from get_user_ids().
                    known = [int(uid) for uid in session.get_user_ids()]
                except Exception as group_error:
                    known = f"unavailable ({group_error})"
                log.error(
                    "[DAVE] Decrypt failed for User %s: %s "
                    "[ready=%s protocol=%s user_in_group=%s group_members=%s]",
                    user_id,
                    exc,
                    session.ready,
                    protocol_version,
                    user_id in known if isinstance(known, list) else '?',
                    known,
                )
                self._logged_decrypt_errors.add(user_id)
            return None

        self._logged_decrypt_errors.discard(user_id)
        return result

    def callback(self, packet_data: bytes) -> None:
        packet = rtp_packet = rtcp_packet = None
        try:
            if not rtp.is_rtcp(packet_data):
                packet = rtp_packet = rtp.decode_rtp(packet_data)
                decrypted_transport = bytes(self.decryptor.decrypt_rtp(packet))
                packet.decrypted_data = self._decrypt_dave(packet, decrypted_transport)
                if packet.decrypted_data is None:
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
