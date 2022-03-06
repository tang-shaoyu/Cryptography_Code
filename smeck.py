# _*_coding : UTF-8 _*_
# 开发人员：tangshaoyu
# 开发时间：2021/11/1 15:12
# 文件名称： simon.PY
# 开发工具： PyCharm
# This code is released under MIT license.


CONFIG = {
    (32, 64): [22, 7, 2, 0],
    (48, 72): [22, 8, 3, 0],
    (48, 96): [23, 8, 3, 1],
    (64, 96): [26, 8, 3, 2],
    (64, 128): [27, 8, 3, 3],
    (96, 96): [28, 8, 3, 2],
    (96, 144): [29, 8, 3, 3],
    (128, 128): [32, 8, 3, 2],
    (128, 192): [33, 8, 3, 3],
    (128, 256): [34, 8, 3, 4],
}


def get_const_seq(seq_id):
    assert seq_id in range(5)
    seq = []

    st = [0, 0, 0, 0, 1]
    for i in range(62):
        f = st[2] ^ st[4]
        # LFSRs not in "the usual way"
        if seq_id in (0, 2):
            st[3] ^= st[4]
        elif seq_id in (1, 3):
            st[1] ^= st[0]
        res = st.pop()
        st.insert(0, f)
        if seq_id >= 2:
            res ^= i % 2
        seq.append(res)

    return tuple(seq)


class SMECK:
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
        self.__seq_id = CONFIG[(block_size, key_size)][3]
        self.__const_seq = get_const_seq(self.__seq_id)
        assert len(self.__const_seq) == 62
        self.__dim = block_size // 4
        self.__mod = 1 << self.__dim
        if master_key is not None:
            self.change_key(master_key)

    def __lshift(self, x, i=1):
        return ((x << i) % self.__mod) | (x >> (self.__dim - i))

    def __rshift(self, x, i=1):
        return ((x << (self.__dim - i)) % self.__mod) | (x >> i)

    def change_key(self, master_key):
        assert 0 <= master_key < (1 << self.key_size)
        c = (1 << self.__dim) - 4
        self.__round_key = []

        kl = master_key >> (self.key_size // 2)
        kr = master_key % (1 << self.key_size // 2)
        assert ((kl << (self.key_size // 2)) | kr) == master_key
        self.__round_key.append(kl % self.__mod)
        self.__round_key.append(kr % self.__mod)
        self.__round_key.append((kl >> self.__dim) % self.__mod)

        """
            每一轮中产生加密所需的k0,k1,k2三个子密钥
            其中k0,k2将在加密的类simon结构中使用
            k1将在加密的类speck结构中使用
        """
        for i in range(self.__num_rounds - 1):
            # 对整个密钥进行循环左移，之后重新产生kl,kr
            master_key = ((master_key << (self.__dim * 2 - self.__dim // 2)) % (1 << self.key_size)) | (
                    master_key >> (self.key_size - (self.__dim * 2 - self.__dim // 2)))
            kl = master_key >> (self.key_size // 2)
            kr = master_key % (1 << self.key_size // 2)

            # print("master_key:" + str(len(bin(master_key))))
            # print("kl:" + str(len(bin(kl))))
            # print("kr:" + str(len(bin(kr))))

            l0 = kl % self.__mod
            l1 = (kl >> self.__dim) % self.__mod
            r0 = kr % self.__mod
            r1 = (kr >> self.__dim) % self.__mod

            # l0,l1作为kl低位的两个分支长度的bit，经过Speck结构，产生用于左右Simon结构的密钥
            k0 = (self.__rshift(l1, self.__const_a) + l0) % self.__mod ^ c ^ self.__const_seq[i % 62]
            k2 = self.__lshift(l0, self.__const_b) ^ l1

            # r1,r2 作为kr低位的分支部分，经过Simon结构产生用于Speck算法的密钥
            f = (self.__lshift(r1) & self.__lshift(r1, 8)) ^ self.__lshift(r1, 2)
            k1 = r0 ^ f ^ c ^ self.__const_seq[i % 62]

            # 将更新后的值返回给master_Key
            kl = kl >> self.__dim * 2
            kl = (kl << self.__dim * 2) | (k0 << self.__dim | k2)
            kr = kr >> self.__dim
            kl = (kl << self.__dim) | k1
            master_key = (kl << self.key_size // 2) | kr

            # 将密钥加入
            self.__round_key.append(k0)
            self.__round_key.append(k1)
            self.__round_key.append(k2)
        return self.__round_key

    def simon_feistel_round(self, l, r, k):
        f = (self.__lshift(l) & self.__lshift(l, 8)) ^ self.__lshift(l, 2)
        return l, r ^ f ^ k

    def speck_feistel_round(self, l, r, k):
        l = (self.__rshift(l, self.__const_a) + r) % self.__mod ^ k
        r = self.__lshift(r, self.__const_b) ^ l
        return l, r

    def speck_re_feistel_round(self, l, r, k):
        r = self.__rshift(r ^ l, self.__const_b)
        l = ((l ^ k) - r) % self.__mod
        l = self.__lshift(l, self.__const_a)
        return l, r

    def encrypt(self, plaintext):
        assert 0 <= plaintext < (1 << self.block_size)
        l0 = plaintext >> self.__dim * 3
        r0 = (plaintext >> self.__dim * 2) % self.__mod
        l1 = (plaintext % (1 << self.__dim * 2)) >> self.__dim
        r1 = plaintext % self.__mod

        for i in range(self.__num_rounds):
            r0, l0 = self.simon_feistel_round(r0, l0, self.__round_key[3 * i])
            l1, r1 = self.simon_feistel_round(l1, r1, self.__round_key[3 * i + 2])
            r0, l1 = self.speck_feistel_round(r0, l1, self.__round_key[3 * i + 1])

            # RT变换
            temp0 = l0
            temp1 = l1
            l0 = r0
            r0 = r1
            l1 = temp0
            r1 = temp1

        ciphertext = (((((l0 << self.__dim) | r0) << self.__dim) | l1) << self.__dim) | r1
        assert 0 <= ciphertext < (1 << self.block_size)
        return ciphertext

    def decrypt(self, ciphertext):
        assert 0 <= ciphertext < (1 << self.block_size)

        l0 = ciphertext >> self.__dim * 3
        r0 = (ciphertext >> self.__dim * 2) % self.__mod
        l1 = (ciphertext % (1 << self.__dim * 2)) >> self.__dim
        r1 = ciphertext % self.__mod

        for i in range(self.__num_rounds - 1, -1, -1):
            # 逆RT
            temp0 = l0
            temp1 = r0
            l0 = l1
            r0 = temp0
            l1 = r1
            r1 = temp1

            r0, l1 = self.speck_re_feistel_round(r0, l1, self.__round_key[3 * i + 1])
            r0, l0 = self.simon_feistel_round(r0, l0, self.__round_key[3 * i])
            l1, r1 = self.simon_feistel_round(l1, r1, self.__round_key[3 * i + 2])

        plaintext = (((((l0 << self.__dim) | r0) << self.__dim) | l1) << self.__dim) | r1
        assert 0 <= plaintext < (1 << self.block_size)
        return plaintext


if __name__ == '__main__':
    const_seq = (
        (1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0,
         0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1,
         0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0),
        (1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0,
         0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1,
         1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0),
        (1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0,
         1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0,
         0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1),
        (1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0,
         1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0,
         1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1),
        (1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0,
         1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0,
         1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1),
    )
    for i in range(len(const_seq)):
        assert const_seq[i] == get_const_seq(i)

    test_vectors = (
        # block_size, key_size, key, plaintext, ciphertext
        (32, 64,
         0x1918111009080100,
         0x65656877,
         0x718ffe40),
        (48, 72,
         0x1211100a0908020100,
         0x6120676e696c,
         0xbc6c613b241a),
        (48, 96,
         0x1a18181211100a0908020100,
         0x72696320646e,
         0x4e9cbe7184f2),
        (64, 96,
         0x131211100b0a090803020100,
         0x6f7220676e696c63,
         0xbeb2aa58a91ef58b),
        (64, 128,
         0x1b1a1818131211100b0a090803020100,
         0x656b696c20646e75,
         0x50f068f2e5c1bec1),
        (96, 96,
         0x0d0c0b0a0908050403020100,
         0x2072616c6c69702065687420,
         0x7b1e9de8103e904358ae2c70),
        (96, 144,
         0x1514131211100d0c0b0a0908050403020100,
         0x74616874207473756420666f,
         0xdc10e4d94284427da84a99d5),
        (128, 128,
         0x0f0e0d0c0b0a09080706050403020100,
         0x63736564207372656c6c657661727420,
         0x47db96a7dcd10b17bbbbe28d522a815f),
        (128, 192,
         0x17161514131211100f0e0d0c0b0a09080706050403020100,
         0x206572656874206e6568772065626972,
         0x979f4af186c2783b3e9babbbc41fdf09),
        (128, 256,
         0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100,
         0x74206e69206d6f6f6d69732061207369,
         0xaccec351ac7429004cb228b237eeae2d)
    )

    # test_vectors = (
    #     # block_size, key_size, key, plaintext, ciphertext
    #     (64, 128,
    #      0x00000000000000000000000000000000,
    #      0x0000000000000000,
    #      0x10315aaf04f5b277),
    #     (64, 128,
    #      0xffffffffffffffffffffffffffffffff,
    #      0x0000000000000000,
    #      0x909e6f3c6c75e92d),
    #     (64, 128,
    #      0x00000000000000000000000000000000,
    #      0xffffffffffffffff,
    #      0x2496cbd8ef6c5da7),
    #     (64, 128,
    #      0xffffffffffffffffffffffffffffffff,
    #      0xffffffffffffffff,
    #      0xc47a53a989e4a92a),
    #     (64, 128,
    #      0x1b1a1818131211100b0a090803020100,
    #      0x656b696c20646e75,
    #      0x50f068f2e5c1bec1)
    # )
    # print()
    # print()
    # print()
    # print()
    for bsize, ksize, key, plain, cipher in test_vectors:
        my_smeck = SMECK(bsize, ksize, key)
        encrypted = my_smeck.encrypt(plain)
        # cipher_text = hex(encrypted).replace("0x", '')
        # plain = hex(plain).replace("0x", '')
        # n =len(plain)//4
        # plain_text = ""
        # final_cipher= ""
        # for i in range(4):
        #     plain_text += plain[n*i:n*(i+1)]+' '
        #     final_cipher += cipher_text[n*i:n*(i+1)]+' '
        #
        # keys = hex(key).replace("0x", '')
        # final_key = ""
        # length = len(keys)
        # for i in range(length//n):
        #     final_key += keys[n*i:n*(i+1)]+' '
        #
        # print("   "+str(bsize)+"/"+str(ksize))
        # print("    plaintext:"+plain_text)
        # print("          key:"+final_key)
        # print("   ciphertext:"+final_cipher)
        # print()
        print(hex(encrypted))
        assert encrypted == cipher
        for i in range(1000):
            encrypted = my_smeck.encrypt(encrypted)
        for i in range(1000):
            encrypted = my_smeck.decrypt(encrypted)
        decrypted = my_smeck.decrypt(encrypted)
        print(hex(decrypted))
        assert decrypted == plain

    print("All tests passed")
