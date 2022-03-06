# _*_coding : UTF-8 _*_
# 开发人员：tangshaoyu
# 开发时间：2021/11/3 20:54
# 文件名称： test_avalanche_degree.PY
# 开发工具： PyCharm
import string
import random

from smeck import SMECK
from simon import SIMON
from Loong import Loong
from algorithm_two import Algorithm


# 随机生成初始明文
def avalanche_degree(blocksize, keysize, key):
    all_values = []
    for i in range(100):
        # 随机生成一组明文,blocksize//8 个字节
        plain = ''.join(random.sample(string.ascii_letters + string.digits, blocksize // 8))

        plain_text = ''
        for i in plain:
            plain_text += hex(ord(i)).replace("0x", '')
        assert len(plain_text) == 2 * blocksize // 8
        plain_text = "0x" + plain_text

        plaintext = int(plain_text, 16)
        # my_smeck = SMECK(blocksize, keysize, key)
        # my_simon = SIMON(blocksize, keysize, key)
        # my_loong = Loong(blocksize, keysize, key)
        my_algorithm = Algorithm(blocksize, keysize, key)
        y_values = []
        # 对一组固定的明文测量将每一bit的雪崩效应
        # p = my_smeck.encrypt(plaintext)
        # p = my_simon.encrypt(plaintext)
        # p = int(my_loong.martix_to_hex(my_loong.encryption(my_loong.change_plain(plaintext))), 16)
        p = my_algorithm.encrypt(plaintext)
        for i in range(blocksize):
            # p0 = my_smeck.encrypt(plaintext ^ (1 << i))
            # p0 = my_simon.encrypt(plaintext ^ (1 << i))
            # p0 = int(my_loong.martix_to_hex(my_loong.encryption(my_loong.change_plain(plaintext ^ (1 << i)))), 16)
            p0 = my_algorithm.encrypt(plaintext ^ (1 << i))
            temp = bin(p ^ p0).replace("0b", '')

            # 统计1的个数
            num = 0
            for j in range(len(temp)):
                if temp[j] == '1':
                    num += 1
            y_values.append(num)
        all_values.append(y_values)
    return all_values


if __name__ == '__main__':
    all_values = avalanche_degree(64, 64, 0x1918111009080100)
    for i in range(len(all_values)):
        print(all_values[i])
