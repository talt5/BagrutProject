from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class RSAEncryption:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_key(self):
        # 2048 bit is size of key
        self.private_key = RSA.generate(2048)
        self.public_key = self.key_to_bytes(self.private_key.public_key())

    def key_to_bytes(self, key):
        return key.export_key()

    def bytes_to_key(self, data):
        return RSA.import_key(data)

    # encrypt data using public, cipher texts are different due to semi randomized padding
    def encrypt(self, data):
        print(self.public_key)
        cipher = PKCS1_OAEP.new(self.public_key)
        return cipher.encrypt(data)

    def decrypt(self, data):
        if self.private_key is not None:
            cipher = PKCS1_OAEP.new(self.private_key)
            return cipher.decrypt(data)

        print("You don't have the private key!")
        return None

    def set_public_key(self, key):
        self.public_key = key
