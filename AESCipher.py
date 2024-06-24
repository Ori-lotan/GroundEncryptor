import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import hmac

class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha512(key.encode()).digest()

    def encrypt(self, raw):
        # generate the unique IV
        iv = Random.new().read(AES.block_size)

        # slice the 512bit key
        kh = self.key[:32]
        km = self.key[32:]

        # pad data + AES
        raw = self._pad(raw)
        c = AES.new(kh, AES.MODE_CBC, iv).encrypt(raw.encode())

        m = hmac.new(km, c.encode(), hashlib.sha512).digest()
        return base64.b64encode(iv + c + m)

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return AESCipher._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]