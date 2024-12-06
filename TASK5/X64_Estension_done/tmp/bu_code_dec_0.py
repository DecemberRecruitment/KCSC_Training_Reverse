from copy import deepcopy as copy

sboxInv = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

def transpose4x4(m):
    return m[0::4] + m[1::4] + m[2::4] + m[3::4]

def list2hex(list):
    list = list[::-1]
    hex = ""
    for e in list:
        hex += "{:02X}".format(e)
    return hex

def hex2list(hex):
    byte_list = [hex[i:i+2] for i in range(0, len(hex), 2)][::-1]
    hex = ''.join(byte_list)
    lst = []
    if len(hex) % 2 == 0:
        for i in range(len(hex)//2):
            lst.append(int(hex[i*2:i*2+2], 16))
    return lst

def xor(bytelist1, bytelist2):
    res = []
    length = min(len(bytelist1), len(bytelist2))
    for i in range(length):
        res.append(bytelist1[i] ^ bytelist2[i])
    return res

def aesdec_cal(state, roundkey, last=False):
    def rotate(word, n):
        return word[n:]+word[0:n]

    def shift_rows_inv(state):
        for i in range(4):
            state[i*4:i*4+4] = rotate(state[i*4:i*4+4],-i)

    def sub_bytes_inv(state):
        for i in range(16):
            state[i] = sboxInv[state[i]]

    def galoisMult(a, b):
        p = 0
        hiBitSet = 0
        for i in range(8):
            if b & 1 == 1:
                p ^= a
            hiBitSet = a & 0x80
            a <<= 1
            if hiBitSet == 0x80:
                a ^= 0x1b
            b >>= 1
        return p % 256

    def mixColumnInv(column):
        temp = copy(column)
        column[0] = galoisMult(temp[0],14) ^ galoisMult(temp[3],9) ^ \
                    galoisMult(temp[2],13) ^ galoisMult(temp[1],11)
        column[1] = galoisMult(temp[1],14) ^ galoisMult(temp[0],9) ^ \
                    galoisMult(temp[3],13) ^ galoisMult(temp[2],11)
        column[2] = galoisMult(temp[2],14) ^ galoisMult(temp[1],9) ^ \
                    galoisMult(temp[0],13) ^ galoisMult(temp[3],11)
        column[3] = galoisMult(temp[3],14) ^ galoisMult(temp[2],9) ^ \
          galoisMult(temp[1],13) ^ galoisMult(temp[0],11)
        return column
    

    def mix_columns_inv(data):
        new = bytearray(16)
        for i in range(4):
            column = [data[i], data[i+4], data[i+8], data[i+12]]
            column = mixColumnInv(column)
            data[i], data[i+4], data[i+8], data[i+12] = column[0], column[1], column[2], column[3]
            # new[i*4: i*4+4] = column[0], column[1], column[2], column[3]
        return data

    state = xor(state, roundkey)
    if not last:
        state = mix_columns_inv(state)
    shift_rows_inv(state)
    sub_bytes_inv(state)
    return state

def aesdec(dat, k):
    data = transpose4x4(hex2list(dat.hex()))
    key = transpose4x4(hex2list(k.hex()))    
    res = transpose4x4(aesdec_cal(data, key))
    return bytes.fromhex(list2hex(res))

def aesdeclast(dat, k):
    data = transpose4x4(hex2list(dat.hex()))
    key = transpose4x4(hex2list(k.hex()))    
    res = transpose4x4(aesdec_cal(data, key, last=True))
    return bytes.fromhex(list2hex(res))

def pxor(byte_array1, byte_array2):
    if len(byte_array1) != len(byte_array2):
        raise ValueError("Both byte arrays must be of the same length")
    result = [b1 ^ b2 for b1, b2 in zip(byte_array1, byte_array2)]    
    return bytes(result)

byte_array = []
with open('flag.txt.enc', 'rb') as file:
    byte = file.read()
data = byte

anon = [bytes.fromhex('9C C0 72 B7 93 CE 7F BB 98 C4 76 B3 9F C2 73 B7'),
bytes.fromhex('DE BA 40 A9 C1 A4 5D B5 DA BE 44 AD CD A8 51 B9'),
bytes.fromhex('DB 15 FC 32 47 D5 8E 85 D4 1B F1 3E 4C DF 87 8D'),
bytes.fromhex('B1 51 B8 2B 6F EB F8 82 AE 4F A5 37 74 F1 E1 9A'),
bytes.fromhex('F5 CC D5 5F 2E D9 29 6D 69 0C A7 E8 BD 17 56 D6'),
bytes.fromhex('E2 4F 07 CB 53 1E BF E0 3C F5 47 62 92 BA E2 55'),
bytes.fromhex('10 96 89 73 E5 5A 5C 2C CB 83 75 41 A2 8F D2 A9'),
bytes.fromhex('D5 8E BA 93 37 C1 BD 58 64 DF 02 B8 58 2A 45 DA'),
bytes.fromhex('40 C3 6B 99 50 55 E2 EA B5 0F BE C6 7E 8C CB 87'),
bytes.fromhex('D7 94 3F 47 02 1A 85 D4 35 DB 38 8C 51 04 3A 34'),
bytes.fromhex('7B 1B DE 12 3B D8 B5 8B 6B 8D 57 61 DE 82 E9 A7'),
bytes.fromhex('90 FE A5 E2 47 6A 9A A5 45 70 1F 71 70 AB 27 FD'),
bytes.fromhex('6D AC 6E 3F 16 B7 B0 2D 2D 6F 05 A6 46 E2 52 C7')]
isFFtoF0 = b'\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5\xF4\xF3\xF2\xF1\xF0'[::-1]
is0toF = b'\x00\x01\x02\x03\x04\x05\x06\a\b\t\n\v\f\r\x0E\x0F'[::-1]
is10to1F = b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'[::-1]
res = b''

for i in range(0, len(data), 16):
    v12 = data[i:i+16][::-1]
    xmm0 = aesdeclast(v12, anon[12])
    xmm0 = aesdec(xmm0, anon[11])
    xmm0 = aesdec(xmm0, anon[10])
    xmm0 = aesdec(xmm0, anon[9])
    xmm0 = aesdec(xmm0, anon[8])
    xmm0 = aesdec(xmm0, anon[7])
    xmm0 = aesdec(xmm0, anon[6])
    xmm0 = aesdec(xmm0, anon[5])
    xmm0 = aesdec(xmm0, anon[4])
    xmm0 = aesdec(xmm0, anon[3])
    xmm0 = aesdec(xmm0, anon[2])
    xmm0 = aesdec(xmm0, anon[1])
    xmm0 = aesdec(xmm0, anon[0])
    xmm0 = aesdec(xmm0, is10to1F)
    xmm0 = pxor(xmm0, is0toF)
    if i == 0:
        isFFtoF0 = b'\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5\xF4\xF3\xF2\xF1\xF0'[::-1]
    xmm0 = pxor(xmm0, isFFtoF0)
    res+=xmm0[::-1]
    isFFtoF0 = v12

print(res)