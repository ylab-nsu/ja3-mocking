import hashlib

def MD5(string: str) -> str:
    return hashlib.md5(string.encode()).hexdigest()