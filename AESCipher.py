import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import hmac
import rsa

class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha512(key.encode()).digest()

    def encrypt(self, raw, signature_key):
        # generate the unique IV
        iv = Random.new().read(AES.block_size)

        # slice the 512bit key
        kc = self.key[:32]
        km = self.key[32:]

        # pad data + AES
        raw = self._pad(raw)

        encryptedMessage = AES.new(kc, AES.MODE_CBC, iv).encrypt(raw.encode())
        signature = rsa.sign(encryptedMessage, signature_key, 'SHA-512')
        # if you want to see the signature check in action - uncomment the command below
        #encryptedMessage = AES.new(kc, AES.MODE_CBC, iv).encrypt(self._pad('hacked!!!').encode())

        return base64.b64encode(iv + encryptedMessage + signature)

    def decrypt(self, encryptedMsg, public_key):
        # slice the 512bit key
        kc = self.key[:32]
        km = self.key[32:]
        encryptedMsg = base64.b64decode(encryptedMsg)
        iv = encryptedMsg[:AES.block_size]
        m = encryptedMsg[-128:]
        c = encryptedMsg[AES.block_size:-128]
        rsa.verify(c, m, public_key) # if verification failed - error will be thrown

        c = AES.new(kc, AES.MODE_CBC, iv)

        return AESCipher._unpad(c.decrypt(encryptedMsg[AES.block_size:-128])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]