# _*_coding : UTF-8 _*_
# 开发人员：T_shaoyu
# 开发时间：2021/11/15 16:41
# 文件名称： algorithm_two.PY
# 开发工具： PyCharm

s_box = [12, 10, 13, 3, 14, 11, 15, 7, 9, 8, 1, 5, 0, 2, 4, 6]

M_matrix = [[1, 4, 9, 13],
            [4, 1, 13, 9],
            [9, 13, 1, 4],
            [13, 9, 4, 1]]

M_matrix_inverse = [[13, 9, 4, 1],
                    [9, 13, 1, 4],
                    [4, 1, 13, 9],
                    [1, 4, 9, 13]]
CONFIG = {
    (128, 128): (16, 1),
    (128, 192): (22, 2),
    (128, 256): (28, 3),
}

const_seq_spn = [0x1, 0x3, 0x7, 0xf, 0x1f, 0x3e, 0x3d, 0x3b, 0x37, 0x2f, 0x1e,
                 0x3c, 0x39, 0x33, 0x27, 0x0e, 0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c,
                 0x18, 0x30, 0x21, 0x2, 0x5, 0xb, 0x17, 0x2e, 0x1c, 0x38, 0x31]

const_matrix = [[0, 0, 0, 0], [0, 0, 1, 0], [0, 0, 2, 0], [0, 0, 4, 0]]


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


class Algorithm:

    def __init__(self, block_size, key_size, master_key=None):
        assert (block_size, key_size) in CONFIG
        self.block_size = block_size
        self.key_size = key_size
        self.__num_rounds, seq_id = CONFIG[(block_size, key_size)]
        self.__const_seq = get_const_seq(seq_id)
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
        self.__round_key.append(kl >> (self.key_size // 2 - self.__dim))
        self.__round_key.append(((kl % (1 << self.__dim)) << self.__dim) | (kr >> (self.key_size // 2 - self.__dim)))
        self.__round_key.append((kl >> (self.key_size // 2 - self.__dim * 2)) % self.__mod)

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
            l2 = (kl >> self.__dim * 2) % self.__mod
            l3 = kl >> self.__dim * 3
            r0 = kr % self.__mod

            # l3,l2作为kl高位的两个分支长度的bit，经过Spn结构，产生用于左右Simon结构的密钥
            k = int(self.martix_to_hex(
                self.round_function(self.change_text((l3 << self.__dim) | l2), self.get_const_matrix(i))), 16)
            k0 = k >> self.__dim
            k2 = k % self.__mod

            # l1,l0,r0 经过Simon结构产生用于Spn结构的密钥
            f = (self.__lshift(l0) & self.__lshift(l0, 8)) ^ self.__lshift(l0, 2)
            k1 = r0 ^ f ^ c ^ self.__const_seq[i % 62]

            f = (self.__lshift(l1) & self.__lshift(l1, 8)) ^ self.__lshift(l1, 2)
            k3 = r0 ^ f ^ c ^ self.__const_seq[i % 62]

            # 将更新后的值返回给master_Key
            kl = (((k << self.__dim) | ((kl >> self.__dim) % self.__mod)) << self.__dim) | k1
            kr = (k3 << self.__dim * 3) | (kr % (1 << self.__dim * 3))
            master_key = (kl << self.key_size // 2) | kr

            # 将密钥加入
            self.__round_key.append(k0)
            self.__round_key.append((k1 << self.__dim) | k3)
            self.__round_key.append(k2)
        return self.__round_key

    def change_text(self, text):
        state = []
        for i in range(4):
            plains = []
            for j in range(4):
                plains.append(text % (1 << 4))
                text = text >> 4
            state.append(plains)
        return state

    def martix_to_hex(self, state):
        text = ''
        for i in range(len(state) - 1, -1, -1):
            text += ''.join([hex(x) for x in state[i][::-1]]).replace('0x', '')
        return text

    def simon_feistel_round(self, l, r, k):
        f = (self.__lshift(l) & self.__lshift(l, 8)) ^ self.__lshift(l, 2)
        return l, r ^ f ^ k

    def get_const_matrix(self, i):
        a = const_seq_spn[i] >> 3
        b = const_seq_spn[i] % (1 << 3)
        const_matrix[0][3] = a
        const_matrix[1][3] = b
        const_matrix[2][3] = a
        const_matrix[3][3] = b
        return const_matrix

    def __add_round_keys(self, state, r):
        for i in range(len(state)):
            for j in range(len(state[i])):
                state[i][j] = state[i][j] ^ r[i][j]
        return state

    def sub_cells(self, state):
        for i in range(len(state)):
            for j in range(len(state[i])):
                state[i][j] = s_box[state[i][j]]
        return state

    def M_finite_field(self, a, b):
        p = 0
        while a and b:
            if b & 1:  # b%2
                p = p ^ a  # since we're in GF(2^m), addition is an XOR */
            if a & 0x8:  # a=a*x^7(a>0),a >= 2**7(128)
                a = (a << 1) ^ 0x13
            else:
                a = a << 1
            b = b >> 1
        return p

    def mix_rows(self, state):
        results = []
        for i in range(len(state)):
            result = []
            for j in range(len(state[i])):
                x = self.M_finite_field(state[i][0], M_matrix[0][j])
                y = self.M_finite_field(state[i][1], M_matrix[1][j])
                z = self.M_finite_field(state[i][2], M_matrix[2][j])
                w = self.M_finite_field(state[i][3], M_matrix[3][j])
                r = x ^ y ^ z ^ w
                result.append(r)
            results.append(result)
        return results

    def mix_columns(self, state):
        results = []
        for i in range(len(state)):
            result = []
            for j in range(len(state[i])):
                x = self.M_finite_field(M_matrix_inverse[i][0], state[0][j])
                y = self.M_finite_field(M_matrix_inverse[i][1], state[1][j])
                z = self.M_finite_field(M_matrix_inverse[i][2], state[2][j])
                w = self.M_finite_field(M_matrix_inverse[i][3], state[3][j])
                r = x ^ y ^ z ^ w
                result.append(r)
            results.append(result)
        return results

    def round_function(self, state, rk, rc=None):
        if rc:
            return self.__add_round_keys(
                self.sub_cells(self.mix_columns(self.mix_rows(self.sub_cells(self.__add_round_keys(state, rk))))), rc)

        else:
            return self.sub_cells(self.mix_columns(self.mix_rows(self.sub_cells(self.__add_round_keys(state, rk)))))

    def encrypt(self, plaintext):
        assert 0 <= plaintext < (1 << self.block_size)
        l0 = plaintext >> self.__dim * 3
        r0 = (plaintext >> self.__dim * 2) % self.__mod
        l1 = (plaintext % (1 << self.__dim * 2)) >> self.__dim
        r1 = plaintext % self.__mod

        for i in range(self.__num_rounds):
            r0, l0 = self.simon_feistel_round(r0, l0, self.__round_key[3 * i])
            l1, r1 = self.simon_feistel_round(l1, r1, self.__round_key[3 * i + 2])

            p = int(self.martix_to_hex(
                self.round_function(
                    self.change_text((r0 << self.__dim) | l1),
                    self.get_const_matrix(i), self.change_text(self.__round_key[3 * i + 1]),
                )
            ), 16)
            r0 = p >> self.__dim
            l1 = p % self.__mod

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
            p = int(self.martix_to_hex(self.round_function(
                self.change_text((r0 << self.__dim) | l1), self.change_text(self.__round_key[3 * i + 1]),
                self.get_const_matrix(i)
            )), 16)

            r0 = p >> self.__dim
            l1 = p % self.__mod
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
        (128, 128,
         0x1f0e0d0c0b0a09080706050403020100,
         0x63736564207372656c6c657661727420,
         0xcebb85b50a6248bb50ff7f04f179fa83),
        (128, 192,
         0x17161514131211100f0e0d0c0b0a09080706050403020100,
         0x206572656874206e6568772065626972,
         0xcc3bce888004f1e2c057a7e3b99da611),
        (128, 256,
         0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100,
         0x74206e69206d6f6f6d69732061207369,
         0x918afd48153258aad78691a27e2799fe),
    )
    # print()
    # print()
    # print()
    # print()
    for bsize, ksize, key, plain, cipher in test_vectors:
        my_algorithm = Algorithm(bsize, ksize, key)
        encrypted = my_algorithm.encrypt(plain)
        decrypt = my_algorithm.decrypt(encrypted)
        # print("   " + str(bsize) + "/" + str(ksize))
        # print("    plaintext: " + hex(decrypt))
        # print("          key: " + hex(key))
        # print("   ciphertext: " + hex(encrypted))
        # print()
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
        # print(hex(encrypted))
        assert encrypted == cipher
        for i in range(1000):
            encrypted = my_algorithm.encrypt(encrypted)
        for i in range(1000):
            encrypted = my_algorithm.decrypt(encrypted)
        decrypted = my_algorithm.decrypt(encrypted)
        # print(hex(decrypted))
        assert decrypted == plain

    print("All tests passed")
