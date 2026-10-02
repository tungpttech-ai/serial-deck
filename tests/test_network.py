import socket
import threading
import unittest

from serial_deck.uart_client import (
    NetworkTransport,
    is_network_port,
    open_uart_transport,
    parse_network_port,
)


class NetworkPortParsingTest(unittest.TestCase):
    def test_detects_network_schemes(self):
        self.assertTrue(is_network_port("tcp://192.168.1.50:23"))
        self.assertTrue(is_network_port("UDP://10.0.0.2:5000"))
        self.assertFalse(is_network_port("/dev/ttyACM0"))
        self.assertFalse(is_network_port("hub:///tmp/serial-deck.sock"))

    def test_parses_host_port_and_local_udp_port(self):
        self.assertEqual(parse_network_port("tcp://board.local:2000"), ("tcp", "board.local", 2000, 0))
        self.assertEqual(parse_network_port("udp://10.0.0.2:5000?local=6000"), ("udp", "10.0.0.2", 5000, 6000))
        self.assertEqual(parse_network_port("udp://:5000"), ("udp", "", 5000, 0))

    def test_rejects_incomplete_endpoints(self):
        for bad in ("tcp://192.168.1.50", "tcp://:23", "udp://h:99999", "udp://h:1?local=x"):
            with self.assertRaises(ValueError, msg=bad):
                parse_network_port(bad)


class NetworkTransportTest(unittest.TestCase):
    def test_tcp_round_trip_and_peer_close(self):
        server = socket.create_server(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def echo_once():
            conn, _ = server.accept()
            with conn:
                conn.sendall(b"login: ")
                conn.sendall(conn.recv(64).upper())

        worker = threading.Thread(target=echo_once, daemon=True)
        worker.start()
        transport = open_uart_transport(f"tcp://127.0.0.1:{port}", 115200, 0.5)
        self.assertIsInstance(transport, NetworkTransport)
        try:
            self.assertEqual(transport.read(), b"login: ")
            transport.write(b"root\n")
            self.assertEqual(transport.read(), b"ROOT\n")
            worker.join(2)
            with self.assertRaises(OSError):
                transport.read()
        finally:
            transport.close()
            server.close()

    def test_tcp_rejects_modem_line_control(self):
        server = socket.create_server(("127.0.0.1", 0))
        transport = NetworkTransport(f"tcp://127.0.0.1:{server.getsockname()[1]}", 0.2)
        try:
            for call in (transport.get_modem_lines, transport.hard_reset,
                         transport.enter_bootloader, transport.send_break):
                with self.assertRaises(OSError):
                    call()
        finally:
            transport.close()
            server.close()

    def test_udp_client_and_listen_modes(self):
        device = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        device.bind(("127.0.0.1", 0))
        device.settimeout(1.0)
        device_port = device.getsockname()[1]
        client = NetworkTransport(f"udp://127.0.0.1:{device_port}", 0.5)
        try:
            client.write(b"ping")
            data, peer = device.recvfrom(64)
            self.assertEqual(data, b"ping")
            device.sendto(b"pong", peer)
            self.assertEqual(client.read(), b"pong")
        finally:
            client.close()

        listener = NetworkTransport("udp://:0?local=0", 0.5)
        try:
            with self.assertRaises(OSError):
                listener.write(b"no peer yet")
            listen_port = listener._socket.getsockname()[1]
            device.sendto(b"hello", ("127.0.0.1", listen_port))
            self.assertEqual(listener.read(), b"hello")
            listener.write(b"reply")
            self.assertEqual(device.recvfrom(64)[0], b"reply")
        finally:
            listener.close()
            device.close()


if __name__ == "__main__":
    unittest.main()
