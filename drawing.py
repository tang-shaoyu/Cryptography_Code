# _*_coding : UTF-8 _*_
# 开发人员：tangshaoyu
# 开发时间：2021/11/4 10:26
# 文件名称： drawing.PY
# 开发工具： PyCharm
from matplotlib.ticker import MultipleLocator

from test_avalanche_degree import avalanche_degree
import numpy as np
import matplotlib.pyplot as plt

# smeck test_vectors
# test_vectors = (
#     # block_size, key_size, key
#     # (32, 64,
#     #  0x1918111009080100),
#     # (48, 72,
#     #  0x1211100a0908020100
#     #  ),
#     # (48, 96,
#     #  0x1a19181211100a0908020100
#     #  ),
#     # (64, 96,
#     #  0x131211100b0a090803020100
#     #  ),
#     # (64, 128,
#     #  0x1b1a1918131211100b0a090803020100
#     #  ),
#     # (96, 96,
#     #  0x0d0c0b0a0908050403020100
#     #  ),
#     # (96, 144,
#     #  0x1514131211100d0c0b0a0908050403020100
#     #  ),
#     (128, 128,
#      0x0f0e0d0c0b0a09080706050403020100
#      ),
#     # (128, 192,
#     #  0x17161514131211100f0e0d0c0b0a09080706050403020100
#     #  ),
#     # (128, 256,
#     #  0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
#     #  )
# )

# # loong test_vectors
# test_vectors = (
#     # block_size, key_size, key, plaintext, ciphertext
#     (64, 64,
#      0x6da7d7ca434762b1),
#     (64, 80,
#      0x6da7d7ca434762b1f85a),
#     (64, 128,
#      0x6da7d7ca434762b1f85a666868a18c23),
# )

# 结构二测试向量
test_vectors = (
    # block_size, key_size, key, plaintext, ciphertext
    (128, 128,
     0x1f0e0d0c0b0a09080706050403020100),
    # (128, 192,
    #  0x17161514131211100f0e0d0c0b0a09080706050403020100),
    # (128, 256,
    #  0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100),
)


def drawing_picture(blocksize, keysize, key):
    all_values = avalanche_degree(blocksize, keysize, key)

    # 100次实验中，每一bit位置上的平均雪崩效应
    average_value = np.mean(all_values, axis=0)

    # 100次实验中，每一bit位置上的方差，也可以认为是不确定度
    variance_value = np.var(all_values, axis=0)

    print("all_average_value: ", average_value)
    print("average_avalanche: ", np.mean(average_value))
    print("variance: ", variance_value)
    print("average_var: ", np.mean(variance_value))
    x_values = list(range(blocksize))
    y_values = average_value

    fig, ax = plt.subplots(figsize=(12, 8))
    plt.plot(x_values, y_values, 'k-', linewidth=2)
    if blocksize < 96:
        point_size = 50
    else:
        point_size = 25
    plt.scatter(x_values, y_values, s=point_size, c='k', marker='s')

    for i in range(len(x_values)):
        ax.hlines(y_values[i] - variance_value[i] / 2, i - 0.3, i + 0.3, colors='red')
        ax.vlines(i, y_values[i] - variance_value[i] / 2, y_values[i] + variance_value[i] / 2, linestyles='dashed',
                  colors='red')
        ax.hlines(y_values[i] + variance_value[i] / 2, i - 0.3, i + 0.3, colors='red')
    # 设置图表标题
    plt.title("Avalanche effect", fontsize=24)
    plt.xlabel("Bit position from 0 " + "to " + str(blocksize - 1), fontsize=14)
    plt.ylabel("Average avalanche degree", fontsize=14)

    # 设置y坐标轴范围以及刻度大小
    y_major_locator = MultipleLocator(2)
    ax.yaxis.set_major_locator(y_major_locator)
    plt.ylim((blocksize // 4 + 2, blocksize * 3 // 4 - 2))

    # 设置标记刻度的大小
    plt.tick_params(axis='both', which='major', labelsize=14)
    path = 'D:\\picture\\blocksize' + (str(blocksize)) + '_' + (str(keysize)) + ".png"
    plt.savefig(path)
    # plt.show()


for bsize, ksize, key in test_vectors:
    drawing_picture(bsize, ksize, key)
