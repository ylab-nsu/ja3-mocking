import pytest
from main import read_wireshark_file, get_JA3_from_packet, get_hash

def test1():
    file_name = "test2.pcap"
    packets = read_wireshark_file(file_name)
    for pkt in packets:
        assert get_JA3_from_packet(pkt) == get_hash(packets[pkt])
