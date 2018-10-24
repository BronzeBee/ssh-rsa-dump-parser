#!/usr/bin/python

import sys
import base64
from pyasn1.type import univ
from pyasn1.codec.der import encoder


# Snippet from sshkey-grab (https://github.com/NetSPI/sshkey-grab)
def unpack_bigint(buf):
    v = 0
    for c in buf:
        v *= 256
        v += ord(c)
    return v


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('No modular inverse')
    return x % m


class MemoryStream:

    def __init__(self, memory, offset=0):
        self.memory = memory
        self.offset = offset

    def peek(self, start, length):
        return self.memory[self.offset + start:self.offset + start + length]

    def read_int(self, length=4):
        v = self.memory[self.offset:self.offset + length]
        self.offset += length
        return unpack_bigint(v)

    def skip(self, n):
        self.offset += n

    def read_str(self, length):
        s = self.memory[self.offset:self.offset + length]
        self.offset += length
        return s

    def find(self, sequence):
        if sequence in self.memory[self.offset:]:
            return self.memory[self.offset:].index(sequence)
        return -1

    def remaining(self):
        return self.memory[self.offset:]


class MemoryParser:

    def __init__(self, in_file_name, out_file_name):
        self.out_file_name = out_file_name
        self.num_saved = 0
        with open(in_file_name, "rb") as in_file:
            self.stream = MemoryStream(in_file.read())

    def read_public_key(self):
        # Length of 'ssh-rsa' string (0x00000007)
        self.stream.skip(4)
        # 'ssh-rsa' string
        self.stream.skip(len("ssh-rsa"))
        # Length of public exponent in bytes (32-bit integer)
        e_length = self.stream.read_int()
        # Public exponent
        e = self.stream.read_int(e_length)
        # Length of modulus in bytes (32-bit integer)
        n_length = self.stream.read_int()
        # Modulus
        n = self.stream.read_int(n_length)
        return n, e


    def read_private_key(self):
        # Length of 'ssh-rsa' string (0x00000007)
        self.stream.skip(4)
        # 'ssh-rsa' string
        self.stream.skip(len("ssh-rsa"))
        # Length of public key part in bytes (32-bit integer)
        self.stream.skip(4)
        # Public key part
        n, e = self.read_public_key()
        # ??? seems like garbage TODO find purpose of these bytes
        self.stream.skip(13)
        # Length of first prime in bytes (32-bit integer)
        p_length = self.stream.read_int()
        # First prime
        p = self.stream.read_int(p_length)
        # Length of second prime in bytes (32-bit integer)
        q_length = self.stream.read_int()
        # Second prime
        q = self.stream.read_int(q_length)
        if n == p * q:
            print("[+] Private key confirmed to be valid")
        else:
            print("[-] Detected private key seems to be invalid (n != pq)")
            return
        # Calculate the remaining parameters
        d = modinv(e, (p - 1) * (q - 1))
        e1 = d % (p - 1)
        e2 = d % (q - 1)
        c = modinv(q, p)
        return n, e, d, p, q, e1, e2, c

    def search_for_key(self):
        while True:
            index = self.stream.find("ssh-rsa")
            if index < 0:
                break
            self.stream.skip(index - 4)
            print("[+] Found RSA key at %s" % hex(index - 4))
            head = self.stream.peek(4 + len("ssh-rsa") + 8, 7)

            if head != "ssh-rsa":
                # This is public exponent, not public part of private key
                print("[-] Detected key appears to be public key, skipping")
                self.stream.skip(4 + len("ssh-rsa"))
                continue
            key = self.read_private_key()
            self.save_private_key(key)

    def save_private_key(self, key):
        self.num_saved += 1

        # Snippet from sshkey-grab (https://github.com/NetSPI/sshkey-grab)
        seq = (
            univ.Integer(0),
            univ.Integer(key[0]),
            univ.Integer(key[1]),
            univ.Integer(key[2]),
            univ.Integer(key[3]),
            univ.Integer(key[4]),
            univ.Integer(key[5]),
            univ.Integer(key[6]),
            univ.Integer(key[7]),
        )

        struct = univ.Sequence()

        for i in range(len(seq)):
            struct.setComponentByPosition(i, seq[i])
        raw = encoder.encode(struct)
        data = base64.b64encode(raw)
        width = 64
        chopped = [data[i:i + width] for i in range(0, len(data), width)]
        content = """-----BEGIN RSA PRIVATE KEY-----
%s
-----END RSA PRIVATE KEY-----
        """ % '\n'.join(chopped)
        key_file_name = self.out_file_name + "." + str(self.num_saved)
        with open(key_file_name, "wt") as out:
            out.write(content)
            print("[+] Saved key as '%s'" % key_file_name)


if __name__ == "__main__":
    parser = MemoryParser(sys.argv[1], sys.argv[2])
    parser.search_for_key()
