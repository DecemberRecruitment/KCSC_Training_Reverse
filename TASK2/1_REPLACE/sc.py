

cipher = [
    # 0x56, 0x64, 0x6C, 0x4B, 0x65, 0x39, 0x75, 0x70, 0x66, 0x42, 
    # 0x46, 0x6B, 0x6B, 0x4F, 0x30, 0x4C
    0x4b6c6456, 0x70753965, 0x6b464266, 0x4c304f6b
]

flag_en = [
    # 0x19, 0x2C, 0x30, 0x2A, 0x79, 0xF9, 0x54, 0x02, 0xB3, 0xA9, 
    # 0x6C, 0xD6, 0x91, 0x80, 0x95, 0x04, 0x29, 0x59, 0xE8, 0xA3, 
    # 0x0F, 0x79, 0xBD, 0x86, 0xAF, 0x05, 0x13, 0x6C, 0xFE, 0x75, 
    # 0xDB, 0x2B, 0xAE, 0xE0, 0xF0, 0x5D, 0x88, 0x4B, 0x86, 0x89, 
    # 0x33, 0x66, 0xAC, 0x45, 0x9A, 0x6C, 0x78, 0xA6
    0x2a302c19, 0x0254f979, 0xd66ca9b3, 0x04958091, 0xa3e85929, 0x86bd790f, 0x6c1305af, 0x2bdb75fe, 0x5df0e0ae, 0x89864b88, 
    0x45ac6633, 0xa6786c9a
]

import sys
from ctypes import *

def encipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0)
    delta = 0x9e3779b9
    n = 32
    w = [0,0]

    while(n>0):
        sum.value += delta
        y.value += ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        z.value += ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w

def decipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0xc6ef3720)
    delta = 0x9e3779b9
    n = 32
    w = [0,0]

    while(n>0):
        z.value -= ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        y.value -= ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        sum.value -= delta
        n -= 1

    w[0] = y.value
    w[1] = z.value
    return w

if __name__ == "__main__":
    # ans = []
    # for i in range(0, len(input_flag), 2):
    #     v = input_flag[i:i+2:1]
    #     k = cipher
    #     tmp = encipher(v, k)
    #     ans += tmp

    # for i in ans: print(hex(i))

# for i in range(0, len(cipher), 4):
#     result = (cipher[i + 3] << 24) | (cipher[i + 2] << 16) | (cipher[i + 1] << 8) | cipher[i]
#     print(f'0x{result:08x}', end = ', ')

# for i in range(0, len(flag_en), 4):
#     result = (flag_en[i + 3] << 24) | (flag_en[i + 2] << 16) | (flag_en[i + 1] << 8) | flag_en[i]
#     print(f'0x{result:08x}', end = ', ')

    ans = []

    for i in range(0, len(flag_en), 2):
        v = flag_en[i:i+2:1]
        k = cipher
        tmp = decipher(v, k)
        ans += tmp

    for i in ans:
        while i: 
            print(end = chr(i & 0xff))
            i >>= 8





