# _*_coding : UTF-8 _*_
# 开发人员：tangshaoyu
# 开发时间：2021/11/1 15:13
# 文件名称： speck.PY
# 开发工具： PyCharm

CONFIG = {
    (32, 64): [22, 7, 2],
    (48, 72): [22, 8, 3],
    (48, 96): [23, 8, 3],
    (64, 96): [26, 8, 3],
    (64, 128): [27, 8, 3],
    (96, 96): [28, 8, 3],
    (96, 144): [29, 8, 3],
    (128, 128): [32, 8, 3],
    (128, 192): [33, 8, 3],
    (128, 256): [34, 8, 3],
}


class SPECK:
    """
    one of the two lightweight block ciphers designed by NSA
    this one is optimized for hardware implementation
    """

    def __init__(self, block_size, key_size, master_key=None):
        assert (block_size, key_size) in CONFIG
        self.block_size = block_size
        self.key_size = key_size
        self.__num_rounds = CONFIG[(block_size, key_size)][0]
        self.__const_a = CONFIG[(block_size, key_size)][1]
        self.__const_b = CONFIG[(block_size, key_size)][2]
        self.__dim = block_size // 2
        self.__mod = 1 << self.__dim
        if master_key is not None:
            self.change_key(master_key)

    def __lshift(self, x, i=1):
        return ((x << i) % self.__mod) | (x >> (self.__dim - i))

    def __rshift(self, x, i=1):
        return ((x << (self.__dim - i)) % self.__mod) | (x >> i)

    def change_key(self, master_key):
        assert 0 <= master_key < (1 << self.key_size)
        m = self.key_size // self.__dim
        self.__round_key = []
        self.__lsequence = []
        self.__round_key.append(master_key % self.__mod)
        master_key >>= self.__dim
        for i in range(m - 1):
            self.__lsequence.append(master_key % self.__mod)
            master_key >>= self.__dim
        for i in range(self.__num_rounds - 1):
            l = self.__rshift(self.__lsequence[i], self.__const_a)
            l = (l + self.__round_key[-1]) % self.__mod ^ i
            k = self.__lshift(self.__round_key[-1], self.__const_b)
            k ^= l
            self.__lsequence.append(l)
            self.__round_key.append(k)


    def __feistel_round(self, l, r, k):
        l = (self.__rshift(l, self.__const_a) + r) % self.__mod ^ k
        r = self.__lshift(r, self.__const_b) ^ l
        return l, r

    def __re_feistel_round(self, l, r, k):
        r = self.__rshift(r ^ l, self.__const_b)
        l = ((l ^ k) - r) % self.__mod
        l = self.__lshift(l, self.__const_a)
        return l, r

    def encrypt(self, plaintext):
        assert 0 <= plaintext < (1 << self.block_size)
        l = plaintext >> self.__dim
        r = plaintext % self.__mod
        for i in range(self.__num_rounds):
            l, r = self.__feistel_round(l, r, self.__round_key[i])
        ciphertext = (l << self.__dim) | r
        assert 0 <= ciphertext < (1 << self.block_size)
        return ciphertext

    def decrypt(self, ciphertext):
        assert 0 <= ciphertext < (1 << self.block_size)
        l = ciphertext >> self.__dim
        r = ciphertext % self.__mod
        for i in range(self.__num_rounds - 1, -1, -1):
            l, r = self.__re_feistel_round(l, r, self.__round_key[i])
        plaintext = (l << self.__dim) | r
        assert 0 <= plaintext < (1 << self.block_size)
        return plaintext


if __name__ == '__main__':
    test_vectors = (
        # block_size, key_size, key, plaintext, ciphertext
        (32, 64,
         0x1918111009080100,
         0x6574694c,
         0xa86842f2),
        (48, 72,
         0x1211100a0908020100,
         0x20796c6c6172,
         0xc049a5385adc),
        (48, 96,
         0x1a19181211100a0908020100,
         0x6d2073696874,
         0x735e10b6445d),
        (64, 96,
         0x131211100b0a090803020100,
         0x74614620736e6165,
         0x9f7952ec4175946c),
        (64, 128,
         0x1b1a1918131211100b0a090803020100,
         0x3b7265747475432d,
         0x8c6fa548454e028b),
        (96, 96,
         0x0d0c0b0a0908050403020100,
         0x65776f68202c656761737520,
         0x9e4d09ab717862bdde8f79aa),
        (96, 144,
         0x1514131211100d0c0b0a0908050403020100,
         0x656d6974206e69202c726576,
         0x2bf31072228a7ae440252ee6),
        (128, 128,
         0x0f0e0d0c0b0a09080706050403020100,
         0x6c617669757165207469206564616d20,
         0xa65d9851797832657860fedf5c570d18),
        (128, 192,
         0x17161514131211100f0e0d0c0b0a09080706050403020100,
         0x726148206665696843206f7420746e65,
         0x1be4cf3a13135566f9bc185de03c1886),
        (128, 256,
         0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100,
         0x65736f6874206e49202e72656e6f6f70,
         0x4109010405c0f53e4eeeb48d9c188f43)
    )

    for bsize, ksize, key, plain, cipher in test_vectors:
        my_speck = SPECK(bsize, ksize, key)
        encrypted = my_speck.encrypt(plain)
        assert encrypted == cipher
        for i in range(1000):
            encrypted = my_speck.encrypt(encrypted)
        for i in range(1000):
            encrypted = my_speck.decrypt(encrypted)
        decrypted = my_speck.decrypt(encrypted)
        assert decrypted == plain

    print("All tests passed")
