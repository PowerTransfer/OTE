import socket
from hashlib import sha1
import numpy as np
from Crypto.Util import number
import gmpy2
import pickle

POWMOD_GMP_SIZE = pow(2, 64)

class Sender():
    def __init__(self, msgs, k=5, random_bit=216):
        self.msgs = msgs
        self.k = k
        self.rdOracle = sha1()
        self.random_num = number.getRandomNumber(random_bit)

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

    def hash(self, data):
        return sha1(data).hexdigest()

    def generate_s(self):
        self.s = list(np.random.randint(0, 2, self.k))

    def encrypt_s(self, pks_ns):
        pks = pks_ns[0]
        ns = pks_ns[1]
        encrypt_mat = []
        for i, pk in enumerate(pks):
            encrypt_random_num = self.powmod(self.random_num, pk[self.s[i]], ns[i][self.s[i]])
            encrypt_mat.append(encrypt_random_num)
        return encrypt_mat

    def generate_Q(self, mat):
        Q = []
        for i, t in enumerate(mat):
            q = self.byte_xor(t[self.s[i]], self.int_to_bytes(self.random_num), len(self.msgs))
            Q.append(list(q))

        Q = [[i[j] for i in Q] for j in range(len(Q[0]))]
        self.Q = Q

    def encode_msg(self):
        enc_msg = []
        for i, msgs in enumerate(self.msgs):
            qi = self.Q[i]
            qi_s = [self.s[i] ^ qij for i, qij in enumerate(qi)]
            em0 = self.byte_xor(self.str_to_bytes(self.hash(bytes(qi))), self.str_to_bytes(msgs[0]))
            em1 = self.byte_xor(self.str_to_bytes(self.hash(bytes(qi_s))), self.str_to_bytes(msgs[1]))

            enc_msg.append([em0, em1])
        return enc_msg

if __name__ == '__main__':

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 1234))
    server_socket.listen(5)
    server, addr = server_socket.accept()

    message = [
                ["Angel012345678901234", "Devil012345678901234"],
                ["Dog01234567890123456", "Cat01234567890123456"],
                ["Apple012345678901234", "Banana01234567890123"],
                ["Red01234567890123456", "Blue0123456789012345"],
                ["Pizza012345678901234", "HotDog01234567890123"],
                ["Coke0123456789012345", "Spirit01234567890123"],
                ["IcedLatte01234567891", "Mocha012345678912345"]
               ]

    sender = Sender(msgs=message, k=5)
    sender.generate_s()
    pks_ns = pickle.loads(server.recv(102400))
    enceypt_k = sender.encrypt_s(pks_ns)
    server.send(pickle.dumps(enceypt_k))
    enceypt_T = pickle.loads(server.recv(102400))
    sender.generate_Q(enceypt_T)
    enc_msg = sender.encode_msg()
    server.send(pickle.dumps(enc_msg))

    server_socket.close()

