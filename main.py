from clientHello import ClientHello
from typing import List, Optional
from MD5_hashing import MD5
import pyshark

TLS_Versions = []
Ciphers = []
Extensions = []
EllipticCurves = []
EllipticCurvesPointFormats = []


def not_reserved(line: str) -> bool:
    return 'Reserved' not in line


def get_hash(packet: ClientHello) -> str:
    # print(str(packet))
    return MD5(str(packet))


def get_request(hash: str) -> ClientHello:
    packet = ClientHello(0, [], [], [], [])
    if get_hash(packet) == hash:
        return packet


def get_code(e: str, split_separator=" ", strip_separator=" ", base=10) -> int:
    return int(e.strip().split(split_separator)[-1].strip(strip_separator), base)


def read_field(string: str) -> List[int]:
    return [get_code(e) for e in string.split(",")]


def read_ciphers(tls):
    # print(str(tls))
    result = []
    for line in str(tls).split("\n"):
        if 'Cipher Suite:' in line and not_reserved(line):
            result.append(get_code(line, strip_separator="()", base=16))
    return result


def read_extensions(tls) -> List[int]:
    extensions = []
    for line in str(tls).split('\n'):
        if 'Type:' in line and line.split()[0] == 'Type:' and not_reserved(line):
            try:
                extensions.append(get_code(line, strip_separator="()"))
            except:
                continue
    return extensions


def read_elliptic_curves(tls) -> List[int]:
    curves = []
    for line in str(tls).split('\n'):
        if 'Supported Group:' in line and not_reserved(line):
            try:
                curves.append(get_code(line, strip_separator=")", split_separator="(", base=16))
            except:
                continue
    return curves


def read_ec_point_formats(tls) -> List[int]:
    formats = []
    for line in str(tls).split('\n'):
        if 'EC point format:' in line:
            try:
                formats.append(get_code(line, strip_separator=")", split_separator="(", base=16))
            except:
                continue
    return formats


def read_server_name(tls) -> str:

    server_name = list(filter(lambda x: "Server Name:" in x, str(tls).splitlines()))
    result: str
    match len(server_name):
        case 0: result = ""
        case 1: result = server_name[0].split()[-1]
        case _: raise ValueError("Tls cannot have more than 1 server names!")

    return result


def read_client_hello(pkt) -> Optional[ClientHello]:
    if hasattr(pkt, 'tls'):
        tls = pkt.tls
        result = ClientHello()
        if hasattr(tls, 'handshake_version'):
            result['tls_version'] = int(tls.handshake_version.replace(':', ''), 16)
        else:
            result['tls_version'] = None
        result.server_name = read_server_name(tls)
        result['ciphers'] = read_ciphers(tls)
        result['extensions'] = read_extensions(tls)
        result['elliptic_curves'] = read_elliptic_curves(tls)
        result['ec_point_formats'] = read_ec_point_formats(tls)
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
        cl = read_client_hello(pkt)
        if cl is not None:
            result[pkt] = cl
            print(result[pkt].server_name)
    file.close()
    return result


def get_handshake_by_domain(pcapng_file: str, domain: str) -> ClientHello:
    file = pyshark.FileCapture(pcapng_file, display_filter="tls.handshake.type == 1")
    result = []
    for pkt in file:
        cl = read_client_hello(pkt)
        if cl is not None and domain in cl.server_name:
            result.append(cl)
    file.close()
    return result


def main():
    file_name = "test2.pcap"
    clh = read_client_hello(file_name)
