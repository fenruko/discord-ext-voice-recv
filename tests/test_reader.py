import logging
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

import davey

from discord.ext.voice_recv.reader import AudioReader
from discord.ext.voice_recv.sinks import BasicSink


USER_ID = 123456789012345678
SSRC = 42
TRANSPORT_PAYLOAD = b'dave-encrypted-audio'
OPUS_PAYLOAD = b'plain-opus-audio'
RTP_PACKET = struct.pack('>BBHII', 0x80, 0x78, 1, 960, SSRC) + b'transport-encrypted-audio'
LOGGER = 'discord.ext.voice_recv.reader'


class AudioReaderDaveTests(unittest.TestCase):
    def setUp(self):
        self.session = SimpleNamespace(
            ready=True,
            decrypt=Mock(return_value=OPUS_PAYLOAD),
            # davey 0.1.x returns strings, not integers, here.
            get_user_ids=Mock(return_value=[str(USER_ID)]),
        )
        self.connection = SimpleNamespace(dave_protocol_version=1, dave_session=self.session)
        self.voice_client = SimpleNamespace(
            _connection=self.connection,
            _ssrc_to_id={SSRC: USER_ID},
            mode='aead_xchacha20_poly1305_rtpsize',
            secret_key=bytes(32),
            ws=None,
        )
        self.reader = AudioReader(BasicSink(Mock(), decode=False), self.voice_client)
        # Exercise the real RTP parser and callback without starting threads or sockets.
        self.reader.decryptor = Mock()
        self.reader.decryptor.decrypt_rtp.return_value = bytearray(TRANSPORT_PAYLOAD)
        self.reader.packet_router = Mock()
        self.reader.speaking_timer = Mock()

    def receive(self):
        self.reader.callback(RTP_PACKET)

    def assert_dropped(self):
        self.reader.packet_router.feed_rtp.assert_not_called()
        self.reader.speaking_timer.notify.assert_not_called()

    def assert_delivered(self, payload):
        self.reader.packet_router.feed_rtp.assert_called_once()
        packet = self.reader.packet_router.feed_rtp.call_args[0][0]
        self.assertEqual(packet.decrypted_data, payload)
        self.reader.speaking_timer.notify.assert_called_once_with(SSRC)

    def test_decrypt_uses_user_id_then_audio_media_type(self):
        self.receive()

        self.session.decrypt.assert_called_once_with(USER_ID, davey.MediaType.audio, TRANSPORT_PAYLOAD)
        self.assertIsInstance(self.session.decrypt.call_args[0][2], bytes)
        self.assert_delivered(OPUS_PAYLOAD)

    def test_decryption_failure_does_not_retry_with_reversed_arguments(self):
        self.session.decrypt.side_effect = ValueError('Failed to decrypt: NoDecryptorForUser')

        with self.assertLogs(LOGGER, level=logging.ERROR) as logs:
            self.receive()

        self.session.decrypt.assert_called_once_with(USER_ID, davey.MediaType.audio, TRANSPORT_PAYLOAD)
        self.assert_dropped()
        self.assertIn('NoDecryptorForUser', logs.output[0])
        self.assertNotIn(' | ', logs.output[0])

    def test_group_members_are_normalized_for_diagnostics(self):
        self.session.decrypt.side_effect = ValueError('Failed to decrypt: NoDecryptorForUser')

        with self.assertLogs(LOGGER, level=logging.ERROR) as logs:
            self.receive()

        self.assertIn('user_in_group=True', logs.output[0])
        self.assertIn('ready=True', logs.output[0])
        self.assertIn('protocol=1', logs.output[0])

    def test_failed_group_lookup_does_not_hide_original_error(self):
        self.session.decrypt.side_effect = ValueError('Failed to decrypt: NoDecryptorForUser')
        self.session.get_user_ids.side_effect = RuntimeError('group unavailable')

        with self.assertLogs(LOGGER, level=logging.ERROR) as logs:
            self.receive()

        self.assertIn('NoDecryptorForUser', logs.output[0])
        self.assertIn('unavailable (group unavailable)', logs.output[0])
        self.assertIn('user_in_group=?', logs.output[0])
        self.assert_dropped()

    def test_not_ready_session_drops_packets_then_recovers(self):
        self.session.ready = False

        with self.assertLogs(LOGGER, level=logging.WARNING) as logs:
            self.receive()
            self.receive()

        self.assertEqual(len(logs.output), 1)
        self.assertIn('waiting for session keys', logs.output[0])
        self.session.decrypt.assert_not_called()
        self.assert_dropped()

        self.session.ready = True
        self.receive()
        self.assert_delivered(OPUS_PAYLOAD)

    def test_real_unready_dave_session_is_not_treated_as_plaintext(self):
        self.connection.dave_session = davey.DaveSession(1, 123, 456)
        self.assertFalse(self.connection.dave_session.ready)

        with self.assertLogs(LOGGER, level=logging.WARNING):
            self.receive()

        self.assert_dropped()

    def test_missing_session_with_dave_enabled_drops_ciphertext(self):
        self.connection.dave_session = None

        with self.assertLogs(LOGGER, level=logging.WARNING):
            self.receive()

        self.assert_dropped()

    def test_missing_session_is_retried_on_the_next_packet(self):
        self.connection.dave_session = None

        with self.assertLogs(LOGGER, level=logging.WARNING):
            self.receive()

        self.connection.dave_session = self.session
        self.receive()
        self.assert_delivered(OPUS_PAYLOAD)

    def test_protocol_zero_bypasses_dave_even_with_a_stale_session(self):
        self.connection.dave_protocol_version = 0
        self.session.ready = False

        self.receive()

        self.session.decrypt.assert_not_called()
        self.assert_delivered(TRANSPORT_PAYLOAD)

    def test_connections_without_dave_support_still_receive_plaintext(self):
        self.voice_client._connection = SimpleNamespace()

        self.receive()

        self.session.decrypt.assert_not_called()
        self.assert_delivered(TRANSPORT_PAYLOAD)

    def test_unknown_ssrc_is_dropped_until_its_user_is_known(self):
        self.voice_client._ssrc_to_id.clear()

        with self.assertLogs(LOGGER, level=logging.WARNING) as logs:
            self.receive()
            self.receive()

        self.assertEqual(len(logs.output), 1)
        self.assertIn('Could not find matching User ID', logs.output[0])
        self.session.decrypt.assert_not_called()
        self.assert_dropped()

        self.voice_client._ssrc_to_id[SSRC] = USER_ID
        self.receive()
        self.assert_delivered(OPUS_PAYLOAD)

    def test_repeated_errors_are_logged_again_after_a_success(self):
        error = ValueError('Failed to decrypt: NoDecryptorForUser')
        self.session.decrypt.side_effect = [error, error, OPUS_PAYLOAD, error]

        with self.assertLogs(LOGGER, level=logging.ERROR) as logs:
            for _ in range(4):
                self.receive()

        self.assertEqual(len(logs.output), 2)
        self.assertEqual(self.session.decrypt.call_count, 4)
        self.assert_delivered(OPUS_PAYLOAD)

    def test_replacement_session_is_used_without_restarting_reader(self):
        new_session = SimpleNamespace(ready=True, decrypt=Mock(return_value=OPUS_PAYLOAD))
        self.connection.dave_session = new_session

        self.receive()

        self.session.decrypt.assert_not_called()
        new_session.decrypt.assert_called_once_with(USER_ID, davey.MediaType.audio, TRANSPORT_PAYLOAD)
        self.assert_delivered(OPUS_PAYLOAD)

    def test_transport_decryption_failure_never_reaches_dave_or_sink(self):
        self.reader.decryptor.decrypt_rtp.side_effect = ValueError('bad transport packet')

        self.receive()

        self.session.decrypt.assert_not_called()
        self.assert_dropped()

    def test_rtcp_does_not_use_dave(self):
        rtcp_packet = struct.pack('>BBHI', 0x80, 201, 1, SSRC)
        self.reader.decryptor.decrypt_rtcp.return_value = rtcp_packet

        self.reader.callback(rtcp_packet)

        self.reader.decryptor.decrypt_rtcp.assert_called_once_with(rtcp_packet)
        self.reader.packet_router.feed_rtcp.assert_called_once()
        self.session.decrypt.assert_not_called()
        self.assert_dropped()


if __name__ == '__main__':
    unittest.main()
