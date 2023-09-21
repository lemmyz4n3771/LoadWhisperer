from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from hashlib import sha256
import sys

def encrypt(plaintext: bytes, key: bytes) -> tuple:
    # Ensure that the key is 32 bytes long
    hashKey = sha256(key).digest()
    # IV will just be 16 null bytes
    iv = bytes([0] *AES.block_size)
    # Ensure plaintext is padded to AES block length (16 bytes)
    plaintext = Padding.pad(plaintext, AES.block_size)
    # Encrypt with AES in CBC mode
    cipher = AES.new(hashKey, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext), hashKey

def getBytes(file: str) -> bytes:
    with open(file, "rb") as f:
        data = f.read()
    return data

def writeCryptoFiles(ciphertext: bytes, key: bytes):
    with open("pe.enc", "wb") as f:
        f.write(ciphertext)
    f.close()
    with open("key.bin", "wb") as f:
        f.write(key)
    f.close()

def main():
    if len(sys.argv) < 2:
        print("[*] Usage: ./encrypt.py <EXECUTABLE_FILE>")
        exit(1)
    try:
        plaintext = getBytes(sys.argv[0])
    except:
        print("[-] Error occured during file read")
        exit(1)
    ciphertext, key = encrypt(plaintext, b'l3mmyz')
    c = [("0x" + y) for y in ("{:02x}".format(x) for x in ciphertext)]
    k = [("0x" + y) for y in ("{:02x}".format(x) for x in key)]
    print("[+] Encryption success!")
    # In case you want to input the encrypted payload (if it's not too large), uncomment below
    # print("char payload[] = {" + ", ".join(c) + '}')
    print("char aesKey[] = {" + ", ".join(k) + '}')
    print("[*] Writing encrypted file and key to disk")
    writeCryptoFiles(ciphertext, key)
    print("[+] Done!")

if __name__ == "__main__":
    main()