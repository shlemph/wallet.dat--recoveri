import sys
import struct
from bsddb.db import *
from hashlib import sha256

# Dumps the private keys from a wallet.dat file.
# Inspired by pywallet.
# Credits: https://bitcoin.stackexchange.com/questions/13681/opening-wallet-dat-in-python-using-bsddb3

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

if not len(sys.argv) == 2:
    print("Usage: %s <wallet_file>" % sys.argv[2])
    sys.exit(1)

def read_size(buffer, offset):
    size = ord(buffer[offset])
    offset += 1

    if size == 0xfd:
        size = struct.unpack_from("<H", buffer, offset)[0]
        offset += 2
    if size == 0xfe:
        size = struct.unpack_from("<I", buffer, offset)[0]
        offset += 4
    if size == 0xff:
        size = struct.unpack_from("<Q", buffer, offset)[0]
        offset += 8

    return offset, size

def read_string(buffer, offset):
    offset, string_len = read_size(buffer, offset)
    return offset + string_len, buffer[offset: offset + string_len]

def b58_encode(d):
    out = ""
    p = 0
    x = 0

    while ord(d[0]) == 0:
        out += "1"
        d = d[1:]

    for i, v in enumerate(d[::-1]):
        x += ord(v)*(256**i)

    while x > 58**(p+1):
        p += 1

    while p >= 0:
        a, x = divmod(x, 58**p)
        out += B58[a]
        p -= 1

    return out

def b58check_encode(d):
    checksum = sha256(sha256(d).digest()).digest()[:4]
    return b58_encode(d + checksum)


db = DB()
db.open(sys.argv[1], "main", DB_BTREE, DB_RDONLY)

items = db.items()

for item in items:
    k, v = item
    koff, voff = 0, 0
    koff, item_type = read_string(k, koff)

    if item_type == "key":
        koff, pubkey = read_string(k, koff)
        voff, privkey = read_string(v, voff)

        if len(privkey) == 279:
            secret = privkey[9:9+32]
        else:
            secret = privkey[8:8+32]

        if pubkey[0] != "\x04":
            secret += "\x01"

        print(b58check_encode("\x80" + secret))
db.close()