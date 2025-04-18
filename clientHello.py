from dataclasses import dataclass
from typing import List
@dataclass
class ClientHello:
    TLS_verison:    int
    Ciphers:        List[int]
    Extensions:     List[int]
    EllipticCurves: List[int]
    EllipticCurvePointFormats: List[int] 
    
    def __str__(self):
        return str(self.TLS_verison) + \
             "-".join(self.Ciphers) + \
             "-".join(self.Extensions) + \
             "-".join(self.EllipticCurves) + \
             "-".join(self.EllipticCurvePointFormats)
    













