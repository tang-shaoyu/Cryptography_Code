# _*_coding : UTF-8 _*_
# 开发人员：T_shaoyu
# 开发时间：2021/11/28 16:40
# 文件名称： drawing_according_to_formula.PY
# 开发工具： PyCharm
import matplotlib.pyplot as plt
import numpy as np
import pylab as pl

fig, ax = plt.subplots(figsize=(12, 8))
t = np.arange(1, 65, 1)
y = 4.49 * 10 ** 7 * t / (843.5 + 25.0 * t) ** 2
max_y = max(y)
max_x = 0
for i in range(len(t)):
    if y[i] == max_y:
        max_x = t[i]
print(max_x)
print(y)
ax.hlines(max_y, 0, max_x, linestyles='dashed', colors='red')
ax.vlines(max_x, 0, max_y, linestyles='dashed', colors='red')
plt.scatter(max_x, max_y, s=200)
plt.xlim(0, 66)
plt.ylim(0, 600)
pl.plot(t, y)
pl.xlabel('δ', fontproperties='SimHei', fontsize=18)
pl.ylabel('FOM', fontproperties='SimHei', fontsize=18)
pl.title('FOM-δ函数图像', fontproperties='SimHei', fontsize=24)
pl.show()
