key = [
    0x33, 0xBF, 0xAD, 0xDE
]

flag_en = [
    0x7D, 0x08, 0xED, 0x47, 0xE5, 0x00, 0x88, 0x3A, 0x7A, 0x36, 
    0x02, 0x29, 0xE4
]

map = []
for i in range(256): map.append(i)
tmp = 0
for i in range(256):
    tmp = (key[i % len(key)] + tmp + map[i]) % 256
    map[tmp], map[i] = map[i], map[tmp]

tmp1, tmp2 = 0, 0
for i in range(len(flag_en)):
    tmp1 = (tmp1 + 1) % 256
    tmp2 = (tmp2 + map[tmp1]) % 256
    map[tmp1], map[tmp2] = map[tmp2], map[tmp1]
    flag_en[i] ^= map[(map[tmp1] + map[tmp2]) % 256]

for i in flag_en: print(end = chr(i))