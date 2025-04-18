from clientHello import ClientHello

TLS_Versions = []
Ciphers = []
Extensions = []
EllipticCurves = []
EllipticCurvesPointFormats = []


def get_request(hash: str) -> ClientHello:
    packet = ClientHello(0, [], [] , [] , [])
    if get_hash(packet) == hash:
        return packet


def get_hash(packet: ClientHello) -> str:
    return MD5(str(packet))


def MD5(string: str) -> str:
    pass


def handle_packet(packet):
    """
        Будем обрабатывать пакеты, а затем извлекать из них нужную информацию.
        Потом будем помещать объект ClientHello и куда-то напрмиер сохранять.
    """
    pass
