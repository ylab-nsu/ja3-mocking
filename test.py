import pytest
from main import read_wireshark_file, get_JA3_from_packet, get_hash

def test1():
    file_name = "test_1_yadro.pcapng"
    packets = read_wireshark_file(file_name)
    print(packets)
    # for pkt in packets:
    #     print(packets[pkt])
    #     packets[pkt]
    #     assert get_JA3_from_packet(pkt) == get_hash(packets[pkt])
