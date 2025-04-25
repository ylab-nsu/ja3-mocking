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
    print(str(packet))
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


def read_ciphers(tls):
    result = []
    for line in str(tls).split("\n"):
        if 'Cipher Suite:' in line:
            result.append(int(line.split()[-1].strip("()"), 16))

    return result


def read_extensions(tls) -> List[int]:
    extensions = []
    for line in str(tls).split('\n'):
        if 'Type:' in line and line.split()[0] == 'Type:':
            try:
                code = line.strip().split()[-1].strip('()')
                extensions.append(int(code))
            except:
                continue
    return extensions


def read_elliptic_curves(tls) -> List[int]:
    curves = []
    for line in str(tls).split('\n'):
        if 'Supported Group:' in line:
            try:
                hex_code = line.split('(')[-1].strip(')')
                curves.append(int(hex_code, 16))
            except:
                continue
    return curves


def read_ec_point_formats(tls) -> List[int]:
    formats = []
    for line in str(tls).split('\n'):
        if 'EC point format:' in line:
            try:
                hex_code = line.split('(')[-1].strip(')')
                formats.append(int(hex_code, 16))
            except:
                continue
    return formats


def read_client_hello(pkt) -> ClientHello:
    if hasattr(pkt, 'tls'):
        tls = pkt.tls
        result = ClientHello()
        if hasattr(tls, 'handshake_version'):
            result['tls_version'] = int(tls.handshake_version.replace(':', ''), 16)
        else:
            result['tls_version'] = None
        result['ciphers'] = read_ciphers(tls)
        result['extensions'] = read_extensions(tls)
        result['elliptic_curves'] = read_elliptic_curves(tls)
        result['ec_point_formats'] = read_ec_point_formats(tls)
        return result


def get_JA3_from_packet(pkt) -> str:
    if hasattr(pkt, 'tls'):
        tls = pkt.tls
        if hasattr(tls, 'handshake_ja3'):
            print(tls.handshake_ja3_full, end = "\n")
            return tls.handshake_ja3


def read_wireshark_file(pcapng_file: str) -> dict[ClientHello]:
    file = pyshark.FileCapture(pcapng_file, display_filter="tls.handshake.type == 1")
    result = {}
    for pkt in file:
        # for line in (pkt.tls.handshake_extensions_ec_point_formats.all_fields):
        #         print(line)
        # for line in str(pkt.tls).split("\n"):
        #     if 'Cipher Suite:' in line:
        #         print(line)
        # print(pkt.tls.field_names)
        # print(list(filter(lambda x: x.startswith("handshake_cipher"), pkt.tls.field_names)))
        result[pkt] = read_client_hello(pkt)
    file.close()
    return result


def main():
    file_name = "test_2_yadro.pcapng"
    clh = read_client_hello(file_name)
