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
        kc = self.key[:32]
        km = self.key[32:]

        # pad data + AES
        raw = self._pad(raw)

        c = AES.new(kc, AES.MODE_CBC, iv).encrypt(raw.encode())
        m = hmac.new(km, iv + c, hashlib.sha512).digest()

        # if you want to see the signature check in action - uncomment the command below
        #c = AES.new(kc, AES.MODE_CBC, iv).encrypt(self._pad('hacked!!!').encode())
        return base64.b64encode(iv + c + m)

    def decrypt(self, encryptedMsg):
        # slice the 512bit key
        kc = self.key[:32]
        km = self.key[32:]
        encryptedMsg = base64.b64decode(encryptedMsg)

        iv = encryptedMsg[:AES.block_size]
        m = encryptedMsg[-64:]
        ivc = encryptedMsg[:-64]
        c = AES.new(kc, AES.MODE_CBC, iv)
        # check if data was changed using the HMAC
        if hmac.new(km, ivc, hashlib.sha512).digest() != m:
            raise Exception('<<WARNING>> your packet was hacked!!')

        return AESCipher._unpad(c.decrypt(encryptedMsg[AES.block_size:-64])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]