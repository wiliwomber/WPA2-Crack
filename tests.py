import unittest
# from crack import *
from scapy.all import *
from utils import get_handshake_packets, get_package_sender_mac, get_package_receiver_mac, get_nonce, get_mic, get_version, get_type, get_length

TEST_PACKAGE_PATH = "assets/handshake.cap"

# TODO move inside class
# ! Important:  this code assumes that the captured packages contain only 1 handshake

# TODO capital case constants
all_packets = rdpcap(
    TEST_PACKAGE_PATH
)
handshake_packets: List[Any] = get_handshake_packets(all_packets)
access_point_mac = "42:2e:1d:1d:4e:d1"
client_mac = "8a:c7:cc:72:6e:8b"
a_nonce = b'/\x97f\xf5]\xab\xae"U\xc0\x8b\r\x9f\x0fh\x8d\x85\x9d\xb9\x99\xd0-\xd1\xe6\x99\x07z]Q\xc01\x9f'
s_nonce = b"e{t\x92!9~\xe9\r\xdd'\x0e\x92M*q9DeR\xb4GH-!A\xee\xe7\xdd\t\xde\xbb"
second_package_mic = b'db035f064992ddefae67e24ea1af9945'
version = 1
package_type = 3
length = 117


class TestGetPackageInformation(unittest.TestCase):
    def test_get_access_point_mac(self):
        mac_address = get_package_sender_mac(handshake_packets[0])
        self.assertEqual(mac_address, access_point_mac)

    def test_get_client_mac(self):
        mac_address = get_package_receiver_mac(handshake_packets[0])
        self.assertEqual(mac_address, client_mac)

    def test_get_a_nonce(self):
        nonce = get_nonce(handshake_packets[0])
        self.assertEqual(a_nonce, nonce)

    def test_get_s_nonce(self):
        nonce = get_nonce(handshake_packets[1])
        self.assertEqual(s_nonce, nonce)

    def test_get_second_package_mic(self):
        mic = get_mic(handshake_packets[1])
        self.assertEqual(mic, second_package_mic)

    def test_get_version(self):
        package_version = get_version(handshake_packets[1])
        self.assertEqual(package_version, version)

    def test_get_type(self):
        type_package = get_type(handshake_packets[1])
        self.assertEqual(type_package, package_type)

    def test_get_length(self):
        package_length = get_length(handshake_packets[1])
        self.assertEqual(package_length, length)


if __name__ == '__main__':
    unittest.main()
