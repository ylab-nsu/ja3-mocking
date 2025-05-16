from dataclasses import dataclass, field
from typing import List
from src.MD5_hashing import MD5


@dataclass
class ClientHello:
    server_name: str = ""
    TLS_version: int = 0
    Ciphers: List[int] = field(default_factory=list)
    Extensions: List[int] = field(default_factory=list)
    EllipticCurves: List[int] = field(default_factory=list)
    EllipticCurvePointFormats: List[int] = field(default_factory=list)

    def __str__(self):
        return str(self.TLS_version) + "," + \
            "-".join(map(str, self.Ciphers)) + "," + \
            "-".join(map(str, self.Extensions)) + "," + \
            "-".join(map(str, self.EllipticCurves)) + "," + \
            "-".join(map(str, self.EllipticCurvePointFormats))

    def __getitem__(self, item: str) -> List[int] | int:
        match item:
            case "tls_version":
                return self.TLS_version
            case "ciphers":
                return self.Ciphers
            case "extensions":
                return self.Extensions
            case "elliptic_curves":
                return self.EllipticCurves
            case "ec_point_formats":
                return self.EllipticCurvePointFormats
            case _:
                raise NameError("Non-valid item")

    def __setitem__(self, key, value):
        match key:
            case "tls_version":
                self.TLS_version = value
            case "ciphers":
                self.Ciphers = value
            case "extensions":
                self.Extensions = value
            case "elliptic_curves":
                self.EllipticCurves = value
            case "ec_point_formats":
                self.EllipticCurvePointFormats = value
            case _:
                raise NameError("Non-valid key")

    def pprint(self, flag: bool):
        if flag:
            print(
                f"JA3-fingerprint without hashing: \n" +
                f"   {self} \n   with given domain: {self.server_name} \n   " +
                f"hash: {MD5(str(self))}")
        else:
            print(f"JA3-fingerprint without hashing: \n   " +
                  f"{self} \n   with given domain: {self.server_name} \n")
