# _*_coding : UTF-8 _*_
# 开发人员：T_shaoyu
# 开发时间：2021/11/11 15:33
# 文件名称： multiplication_tables.PY
# 开发工具： PyCharm

M_matrix = [[1, 4, 9, 13],
            [4, 1, 13, 9],
            [9, 13, 1, 4],
            [13, 9, 4, 1]]

M_matrix_inverse = [[13, 9, 4, 1],
                    [9, 13, 1, 4],
                    [4, 1, 13, 9],
                    [1, 4, 9, 13]]


def GMUL(a, b):  # Russian Peasant Multiplication algorithm
    p = 0
    while a and b:
        if b & 1:  # b%2
            p = p ^ a  # since we're in GF(2^m), addition is an XOR */
        if a & 0x8:  # a=a*x^7(a>0),a >=
            # 2**7(128)
            a = (a << 1) ^ 0x13
        else:
            a = a << 1
        b = b >> 1
    return p


for i in range(len(M_matrix)):
    result = []
    for j in range(len(M_matrix[i])):
        x = GMUL(M_matrix[i][0], M_matrix_inverse[0][j])
        y = GMUL(M_matrix[i][1], M_matrix_inverse[1][j])
        z = GMUL(M_matrix[i][2], M_matrix_inverse[2][j])
        w = GMUL(M_matrix[i][3], M_matrix_inverse[3][j])
        r = x ^ y ^ z ^ w
        result.append(r)
    print(result)
