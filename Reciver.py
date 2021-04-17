import socket
from hashlib import sha1
import Crypto.Random as Random
from Crypto.PublicKey import RSA
import numpy as np
import gmpy2
import pickle
POWMOD_GMP_SIZE = pow(2, 64)

class Receiver():
    def __init__(self, r, k):
        self.r = r
        self.k = k
        self.generate_rsa()

    def hash(self, data):
        return sha1(data).hexdigest()

    def powmod(self, a, b, c):
        """
        return int: (a ** b) % c
        """
        if a == 1:
            return 1
        if max(a, b, c) < POWMOD_GMP_SIZE:
            return pow(a, b, c)
        else:
            return int(gmpy2.powmod(a, b, c))

    def byte_xor(self, b1, b2, Truncated_len=None):
        if len(b1) >= len(b2):
            byte1, byte2 = b1, b2
        else:
            byte1, byte2 = b2, b1
        result = bytearray(byte1)
        for i, b in enumerate(byte2):
            result[i] ^= b
        result_byte = bytes(result)
        if Truncated_len:
            result_byte = result_byte[:Truncated_len]
        return result_byte

    def int_to_bytes(self, integer):
        """
        Convert an int to bytes
        :param integer:
        :return: bytes
        """
        return integer.to_bytes((integer.bit_length() + 7) // 8, 'big')

    def bytes_to_int(self, bytes_arr):
        """
        Convert bytes to an int
        :param bytes_arr:
        :return: int
        """
        return int.from_bytes(bytes_arr, byteorder='big', signed=False)

    def str_to_bytes(self, str_arr):
        """
        'hello' -> b'hello'
        :param str_arr: str
        :return: bytes
        """
        return bytes(str_arr, 'utf-8')

    def bytes_to_str(self, byte_arr):
        """
        b'hello' -> 'hello'
        :param byte_arr: bytes
        :return: str
        """
        return str(byte_arr, 'utf-8')

    def generate_rsa(self, rsa_bit=1024):
        random_generator = Random.new().read
        pks, ns, dks = [], [], []
        for i in range(self.k):
            pk, n, dk = [], [], []
            rsa0 = RSA.generate(rsa_bit, random_generator)
            pk.append(rsa0.e)
            n.append(rsa0.n)
            dk.append(rsa0.d)
            rsa1 = RSA.generate(rsa_bit, random_generator)
            pk.append(rsa1.e)
            n.append(rsa1.n)
            dk.append(rsa1.d)

            pks.append(pk)
            ns.append(n)
            dks.append(dk)
        self.pks, self.ns, self.dks = pks, ns, dks

    def get_pks(self):
        return [self.pks, self.ns]

    def generate_T(self):
        m = len(self.r)
        mat = []
        for i in range(self.k):
            t0 = list(np.random.randint(0, 2, m))
            t1 = [t ^ self.r[i] for i, t in enumerate(t0)]
            mat.append([t0, t1])
        self.T = mat

    def decrypt_k(self, data):
        k = []
        for i, e_k in enumerate(data):
            k0 = self.powmod(e_k, self.dks[i][0], self.ns[i][0])
            k1 = self.powmod(e_k, self.dks[i][1], self.ns[i][1])
            k.append([k0, k1])
        return k

    def encrypt_T(self, k):
        encrypt_mat = []
        for i, ks in enumerate(k):
            t0_bytes = bytes(self.T[i][0])
            encrypt_t0_bytes = self.byte_xor(t0_bytes, self.int_to_bytes(ks[0]))
            t1_bytes = bytes(self.T[i][1])
            encrypt_t1_bytes = self.byte_xor(t1_bytes, self.int_to_bytes(ks[1]))
            encrypt_mat.append([encrypt_t0_bytes, encrypt_t1_bytes])
        return encrypt_mat

    def decode_msg(self, encode_msg):
        T0 = [i[0] for i in self.T]
        T = [[i[j] for i in T0] for j in range(len(T0[0]))]
        decode_msg = []
        for i, msgs in enumerate(encode_msg):
            dec_msg_bytes = self.byte_xor(msgs[self.r[i]], self.str_to_bytes(self.hash(bytes(T[i]))), 20)
            dec_msg = self.bytes_to_str(dec_msg_bytes)
            decode_msg.append(dec_msg)
        return decode_msg


if __name__ == '__main__':
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 1234))

    choice = [1, 0, 1, 0, 1, 0, 0]
    receiver = Receiver(r=choice, k=5)
    receiver.generate_T()
    pks_ns = receiver.get_pks()
    client.send(pickle.dumps(pks_ns))
    encrypt_k = pickle.loads(client.recv(102400))
    k = receiver.decrypt_k(encrypt_k)
    encrypt_T = receiver.encrypt_T(k)
    client.send(pickle.dumps(encrypt_T))
    enc_msg = pickle.loads(client.recv(102400))

    decode_msg = receiver.decode_msg(enc_msg)
    print('r:', receiver.r)
    print('decode_msg:', decode_msg)
    client.close()

