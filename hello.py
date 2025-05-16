import argparse

from src.wireshark_parsing import get_handshake_by_domain

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Getting client_hello by domain")

    parser.add_argument("file", help="Name of wireshark file")
    parser.add_argument("domain", help="Valid domain")
    parser.add_argument("-hs", "--hashing", action="store_true", help="An optional argument to get hash of JA3 finger print")

    args = parser.parse_args()

    for ch in get_handshake_by_domain(args.file, args.domain):
        ch.pprint(args.hashing)




