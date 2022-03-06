# _*_coding : UTF-8 _*_
# 开发人员：T_shaoyu
# 开发时间：2021/11/11 15:12
# 文件名称： Loong.PY
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
    (64, 64): 16,
    (64, 80): 20,
    (64, 128): 32,
}

const_seq = [0x1, 0x3, 0x7, 0xf, 0x1f, 0x3e, 0x3d, 0x3b, 0x37, 0x2f, 0x1e,
             0x3c, 0x39, 0x33, 0x27, 0x0e, 0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c,
             0x18, 0x30, 0x21, 0x2, 0x5, 0xb, 0x17, 0x2e, 0x1c, 0x38, 0x31]

const_matrix = [[0, 0, 0, 0], [0, 0, 1, 0], [0, 0, 2, 0], [0, 0, 4, 0]]


def get_const_seq():
    seq = []
    i = 0
    st = [0, 0, 0, 0, 0, 1]
    while i < 33:
        seq.append(hex(int(''.join([str(x) for x in st]), 2)))
        value = st[0] ^ st[1] ^ 1
        st = st[1:]
        st.append(value)
        i += 1
    return seq


class Loong:
    def __init__(self, block_size, key_size, master_key=None):
        self.block_size = block_size
        self.key_size = key_size
        self.num_rounds = CONFIG[(block_size, key_size)]
        self.__dim = 4
        self.__mod = 1 << self.__dim
        self.rk0 = []
        self.rk1 = []
        if master_key is not None:
            self.change_key(master_key)

    def get_const_matrix(self, i):
        a = const_seq[i] >> 3
        b = const_seq[i] % (1 << 3)
        const_matrix[0][3] = a
        const_matrix[1][3] = b
        const_matrix[2][3] = a
        const_matrix[3][3] = b
        return const_matrix

    def __add_round_keys(self, state, rk, rc):
        for i in range(len(state)):
            for j in range(len(state[i])):
                state[i][j] = state[i][j] ^ rk[i][j] ^ rc[i][j]
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

    def round_function(self, state, rk, rc):
        return self.__add_round_keys(self.sub_cells(self.mix_columns(self.mix_rows(self.sub_cells(state)))), rk, rc)

    def encryption(self, plaintext):
        rc = self.get_const_matrix(0)
        state = self.__add_round_keys(plaintext, self.rk0, rc)
        for i in range(1, self.num_rounds + 1):
            rc = self.get_const_matrix(i)
            if self.key_size > 64:
                if i % 2 == 1:
                    rk = self.rk1
                else:
                    rk = self.rk0
            else:
                rk = self.rk0
            state = self.round_function(state, rk, rc)
        return state

    def decryption(self, ciphertext):
        rc = self.get_const_matrix(self.num_rounds)
        state = self.__add_round_keys(ciphertext, self.rk0, rc)
        for i in range(1, self.num_rounds + 1):
            rc = self.get_const_matrix(self.num_rounds - i)
            if self.key_size > 64:
                if i % 2 == 1:
                    rk = self.rk1
                else:
                    rk = self.rk0
            else:
                rk = self.rk0
            state = self.round_function(state, rk, rc)
        return state

    def change_key(self, master_key):
        for i in range(4):
            keys = []
            for j in range(4):
                keys.append(master_key % self.__mod)
                master_key = master_key >> self.__dim
            self.rk0.append(keys)
        if self.key_size == 128:
            for i in range(4):
                keys = []
                for j in range(4):
                    keys.append(master_key % self.__mod)
                    master_key = master_key >> self.__dim
                self.rk1.append(keys)
        if self.key_size == 80:
            keys = []
            for j in range(4):
                keys.append(master_key % self.__mod)
                master_key = master_key >> self.__dim
            self.rk1.append(keys)
            self.rk1.append(self.rk0[0])
            self.rk1.append(self.rk0[1])
            self.rk1.append(self.rk0[2])

    def change_plain(self, plaintext):
        state = []
        for i in range(4):
            plains = []
            for j in range(4):
                plains.append(plaintext % self.__mod)
                plaintext = plaintext >> self.__dim
            state.append(plains)
        return state

    def martix_to_hex(self, state):
        text = ''
        for i in range(len(state) - 1, -1, -1):
            text += ''.join([hex(x) for x in state[i][::-1]]).replace('0x', '')
        return text


if __name__ == '__main__':

    # 测试常数序列是否正确
    seq = get_const_seq()
    for i in range(len(seq)):
        assert int(seq[i], 16) == const_seq[i]

    # 测试向量
    test_vectors = (
        # block_size, key_size, key, plaintext, ciphertext
        (64, 64,
         0x0000000000000000,
         0x0000000000000000,
         0x4a9b216ade5d93c0),
        (64, 80,
         0x00000000000000000000,
         0x0000000000000000,
         0x2a984ca15e518f23),
        (64, 128,
         0x00000000000000000000000000000000,
         0x0000000000000000,
         0xdefa24c05cbc166f),
    )
    for bsize, ksize, key, plain, cipher in test_vectors:
        my_loong = Loong(bsize, ksize, key)
        plain_martix = my_loong.change_plain(plain)
        encrypted = my_loong.encryption(plain_martix)
        decrypted = my_loong.decryption(encrypted)
        plaintext = my_loong.martix_to_hex(decrypted)
        ciphertext = my_loong.martix_to_hex(encrypted)

        print("   " + str(bsize) + "/" + str(ksize))
        print("    plaintext: 0x" + plaintext)
        print("          key: " + hex(key))
        print("   ciphertext: 0x" + ciphertext)
        print()
#     for i in range(1000):
#         encrypted = my_loong.encryption(encrypted)
#     for i in range(1000):
#         encrypted = my_loong.decryption(encrypted)
#     decrypted = my_loong.decryption(encrypted)
#     assert decrypted == my_loong.change_plain(plain)
# print("test pass")
