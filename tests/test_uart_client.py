import socket
import unittest
from unittest.mock import MagicMock, patch

from serial_deck import uart_client as cli

from serial_deck.uart_client import (
    ERROR_CODES,
    FRAME_COMMAND,
    STATUSES,
    cobs_decode,
    cobs_encode,
    crc32_ieee,
    decode_frame,
    encode_frame,
    encode_json_frame,
    FRAME_EVENT,
    FRAME_HELLO,
    PENDING_LIMIT,
    UartReader,
    UartSocketTransport,
    make_request,
    validate_request,
)


class CliHubRoutingTest(unittest.TestCase):
    def test_device_selection_routes_cli_through_shared_hub(self):
        manager = MagicMock(endpoint="hub:///tmp/test-channel.sock")
        with patch("serial_deck.hub_client.HubProcessManager", return_value=manager), \
                patch.object(cli, "open_uart_transport", return_value=MagicMock()) as transport, \
                patch.object(cli, "wait_for_response", return_value=0):
            self.assertEqual(cli.main(["--port", "/dev/ttyFAKE0", "hello"]), 0)
        manager.ensure_started.assert_called_once()
        manager.claim_port.assert_called_once_with("/dev/ttyFAKE0", 2000000)
        transport.assert_called_once_with("hub:///tmp/test-channel.sock", 2000000, 0.1)
        manager.stop.assert_called_once()


class ControlCodecTest(unittest.TestCase):
    def test_lifecycle_contract_names(self):
        self.assertIn("accepted", STATUSES)
        self.assertIn("failed", STATUSES)
        self.assertIn("invalid_schema", ERROR_CODES)
        self.assertIn("operation_not_found", ERROR_CODES)

    def test_crc_vector(self):
        self.assertEqual(crc32_ieee(b"123456789"), 0xCBF43926)

    def test_cobs_round_trip_and_zero_delimiter(self):
        for value in (b"", b"abc", b"a\0b\0c", bytes(range(256))):
            encoded = cobs_encode(value)
            self.assertNotIn(0, encoded)
            self.assertEqual(cobs_decode(encoded), value)

    def test_golden_frame(self):
        frame = encode_frame(FRAME_COMMAND, 0, 0x01020304, b'{"type":"hello"}')
        self.assertEqual(
            frame.hex(),
            "030102060403020110157b2274797065223a2268656c6c6f227d1c7ae1a300",
        )
        self.assertEqual(decode_frame(frame), (FRAME_COMMAND, 0, 0x01020304, b'{"type":"hello"}'))

    def test_crc_rejection(self):
        frame = bytearray(encode_frame(FRAME_COMMAND, 0, 1, b"x"))
        frame[-2] ^= 0x01
        with self.assertRaises(ValueError):
            decode_frame(bytes(frame))

    def test_request_validation(self):
        request = {
            "version": 1,
            "request_id": "req-1",
            "command": "input.button",
            "args": {"button": "HOME", "action": "press"},
            "deadline_ms": 3000,
            "idempotency_key": "step-1",
        }
        validate_request(request)
        validate_request({
            "version": 1,
            "request_id": "req-read",
            "command": "query",
            "args": {"kind": "fsm"},
            "deadline_ms": 1000,
        })
        for bad in (
            {**request, "extra": 1},
            {**request, "command": "shell.exec"},
            {**request, "deadline_ms": 30001},
            {**request, "args": {"button": "HOME"}},
            {
                "version": 1,
                "request_id": "q-bad",
                "command": "query",
                "args": {"kind": "logs"},
                "deadline_ms": 1000,
            },
        ):
            with self.assertRaises(ValueError):
                validate_request(bad)

    def test_make_request_assigns_idempotency_only_to_writes(self):
        query = make_request("query", {"kind": "fsm"})
        self.assertNotIn("idempotency_key", query)
        button = make_request("input.button", {"button": "HOME", "action": "press"})
        self.assertEqual(button["idempotency_key"], button["request_id"])

    def test_uart_reader_separates_frame_and_console_log(self):
        frame = encode_json_frame(FRAME_EVENT, 7, {"status": "running"})

        class FakeTransport:
            def __init__(self, data):
                self.data = data

            def read(self, size=4096):
                data, self.data = self.data, b""
                return data

        reader = UartReader(FakeTransport(b"I (42) app: ready\n" + frame))
        records = reader.poll()
        self.assertEqual(records[0], ("log", "I (42) app: ready"))
        self.assertEqual(records[1], ("frame", (FRAME_EVENT, 0, 7, {"status": "running"})))

    def test_uart_reader_recovers_frame_after_interleaved_console_byte(self):
        frame = encode_json_frame(FRAME_EVENT, 9, {"status": "succeeded"})

        class FakeTransport:
            def __init__(self, data):
                self.data = data

            def read(self, size=4096):
                data, self.data = self.data, b""
                return data

        damaged_log = b"W (42) control: post failed\x03: ESP_ERR_TIMEOUT\r\n"
        reader = UartReader(FakeTransport(damaged_log + frame))
        records = reader.poll()
        self.assertEqual(records[0][0], "log")
        self.assertEqual(records[1], ("frame", (FRAME_EVENT, 0, 9, {"status": "succeeded"})))

    def test_uart_reader_bounds_undelimited_input(self):
        reader = UartReader(None)
        records = []
        for _ in range(256):
            records += reader.feed(b"\x01" * 4096)
        self.assertLessEqual(len(reader._pending), PENDING_LIMIT)
        self.assertTrue(records and records[0][1].startswith("[truncated "))
        frame = encode_json_frame(FRAME_EVENT, 3, {"status": "running"})
        self.assertIn(("frame", (FRAME_EVENT, 0, 3, {"status": "running"})),
                      reader.feed(b"\x00" + frame))

    def test_uart_reader_raw_mode_keeps_ansi_console_lines(self):
        reader = UartReader(None, frames=False)
        records = reader.feed(b"\x1b[1;34mbin\x1b[0m  etc\r\nroot@board:~# ")
        self.assertEqual(records, [("log", "\x1b[1;34mbin\x1b[0m  etc")])
        self.assertEqual(reader.feed(b"ls\r\n"), [("log", "root@board:~# ls")])

    def test_hub_socket_eof_is_reported_as_disconnect(self):
        peer, client = socket.socketpair()
        transport = UartSocketTransport.__new__(UartSocketTransport)
        transport._socket = client
        peer.close()
        with self.assertRaisesRegex(OSError, "data socket closed"):
            transport.read()
        client.close()

    def test_hello_frame_round_trip(self):
        frame = encode_json_frame(FRAME_HELLO, 3, {"type": "hello"})
        self.assertEqual(decode_frame(frame)[0], FRAME_HELLO)


if __name__ == "__main__":
    unittest.main()
