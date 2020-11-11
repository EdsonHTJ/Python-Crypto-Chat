from Crypto.Cipher import AES
from Crypto import Random


def AESkeyGen():
    return Random.new().read(AES.block_size)

def en_AES(st,k):

    #key = (bytes(k,'utf-8'))
    key = k
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce

    ciphertext, tag = cipher.encrypt_and_digest(st)
    ciphertext = nonce + ciphertext
    return ciphertext


def dec_AES(st,k):
    #key = (bytes(k,'utf-8'))
    key = k

    nonce = st[:16]
    msg = st[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(msg)
    return plaintext
