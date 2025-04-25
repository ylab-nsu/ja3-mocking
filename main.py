from clientHello import ClientHello
from typing import List
from MD5_hashing import MD5
import pyshark

TLS_Versions = []
Ciphers = []
Extensions = []
EllipticCurves = []
EllipticCurvesPointFormats = []


def get_hash(packet: ClientHello) -> str:
    return MD5(str(packet))


def get_request(hash: str) -> ClientHello:
    packet = ClientHello(0, [], [], [], [])
    if get_hash(packet) == hash:
        return packet


def handle_packet(packet):
    """
        Будем обрабатывать пакеты, а затем извлекать из них нужную информацию.
        Потом будем помещать объект ClientHello и куда-то напрмиер сохранять.
    """
    pass


def get_code(e: str) -> int:
    return int(e.strip().split()[0], 16)


def read_field(string: str) -> List[int]:
    return [get_code(e) for e in string.split(",")]


def read_client_hello(pkt) -> ClientHello:
    if hasattr(pkt, 'tls'):
        tls = pkt.tls
        result = ClientHello()
        if hasattr(tls, 'handshake_version'):
            result['tls_version'] = int(tls.handshake_version.replace(':', ''), 16)
        else:
            result['tls_version'] = None

        if hasattr(tls, 'handshake_ciphersuite'):
            try:
                result['ciphers'] = read_field(tls.handshake_ciphersuite)
            except:
                result['ciphers'] = []
        else:
            result['ciphers'] = []

        if hasattr(tls, 'handshake_extensions_type'):
            try:
                result['extensions'] = read_field(tls.handshake_extensions_type)
            except:
                result['extensions'] = []
        else:
            result['extensions'] = []

        if hasattr(tls, 'handshake_extension_supported_group'):
            try:
                result['elliptic_curves'] = read_field(tls.handshake_extension_supported_group)
            except:
                result['elliptic_curves'] = []
        else:
            result['elliptic_curves'] = []

        if hasattr(tls, 'handshake_extension_ec_point_format'):
            try:
                result['ec_point_formats'] = read_field(tls.handshake_extension_ec_point_format)
            except:
                result['ec_point_formats'] = []
        else:
            result['ec_point_formats'] = []
        return result


def get_JA3_from_packet(pkt) -> str:
    if hasattr(pkt, 'tls'):
        tls = pkt.tls
        if hasattr(tls, 'handshake_ja3'):
            return tls.handshake_ja3


def read_wireshark_file(pcapng_file: str) -> dict[ClientHello]:
    file = pyshark.FileCapture(pcapng_file, display_filter="tls.handshake.type == 1")
    result = {}
    for pkt in file:
        # for i in pkt.tls.handshake_ciphersuites:
        #     print(i)
        #
        # print(list(filter(lambda x: x.startswith("handshake_cipher"), pkt.tls.field_names)))
        result[pkt] = read_client_hello(pkt)
    file.close()
    return result


def main():
    file_name = "test_2_yadro.pcapng"
    clh = read_client_hello(file_name)
