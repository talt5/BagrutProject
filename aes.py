from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class AESEncryption:
    def __init__(self):
        self.key = None

    def generate_key(self):
        # the key is bytes so we can send it using sockets
        # 32 bytes is size of key
        self.key = get_random_bytes(32)

    def encrypt_data(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext = cipher.encrypt(data)
        return ciphertext, cipher.nonce

    def decrypt_data(self, data, nonce):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(data)
        return plaintext

    def set_key(self, key):
        self.key = key

    def get_key(self):
        return self.key

