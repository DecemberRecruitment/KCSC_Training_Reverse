SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

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

def aesenc_cal(state, roundkey, last=False):
    def shift_rows(state):
        state[4], state[5], state[6], state[7] = state[5], state[6], state[7], state[4]
        state[8], state[9], state[10], state[11] = state[10], state[11], state[8], state[9]
        state[12], state[13], state[14], state[15] = state[15], state[12], state[13], state[14]

    def sub_bytes(state):
        for i in range(16):
            state[i] = SBOX[state[i]]

    def mix_columns(state):
        xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

        def mix_column(col):
            t = col[0] ^ col[1] ^ col[2] ^ col[3]
            u = col[0]
            col[0] ^= t ^ xtime(col[0] ^ col[1])
            col[1] ^= t ^ xtime(col[1] ^ col[2])
            col[2] ^= t ^ xtime(col[2] ^ col[3])
            col[3] ^= t ^ xtime(col[3] ^ u)
            return col

        out = [None]*16
        for i in range(0,4):
            out[i::4] = mix_column(state[i::4])
        return out

    sub_bytes(state)
    shift_rows(state)
    if not last:
        state = mix_columns(state)
    return xor(state, roundkey)

def aesenc(dat, k):
    data = transpose4x4(hex2list(dat.hex()))
    key = transpose4x4(hex2list(k.hex()))    
    res = transpose4x4(aesenc_cal(data, key))
    return bytes.fromhex(list2hex(res))

def aesenclast(dat, k):
    data = transpose4x4(hex2list(dat.hex()))
    key = transpose4x4(hex2list(k.hex()))    
    res = transpose4x4(aesenc_cal(data, key, last=True))
    return bytes.fromhex(list2hex(res))

# dat = bytes.fromhex('99CEA0979C8A92A0CFCFC884BCACBCB4')
# k = bytes.fromhex('1F1E1D1C1B1A19181716151413121110')
# print(aesenc(dat, k).hex())
# dat = bytes.fromhex('0D439788841B6ECA6DAEC0E27E1592B3')
# k = bytes.fromhex('6DAC6E3F16B7B02D2D6F05A646E252C7')
# print(aesenclast(dat, k).hex())

# def pxor(byte_array1, byte_array2):
#     if len(byte_array1) != len(byte_array2):
#         raise ValueError("Both byte arrays must be of the same length")
#     result = [b1 ^ b2 for b1, b2 in zip(byte_array1, byte_array2)]    
#     return bytes(result)

# byte_array1 = bytes.fromhex('66315F6863756D5F3030377B4353434B')
# byte_array2 = bytes.fromhex('F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF')
# print(pxor(byte_array1, byte_array2).hex())


# data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E"
# print(len(data))
# anon = [bytes.fromhex('9C C0 72 B7 93 CE 7F BB 98 C4 76 B3 9F C2 73 B7'),
# bytes.fromhex('DE BA 40 A9 C1 A4 5D B5 DA BE 44 AD CD A8 51 B9'),
# bytes.fromhex('DB 15 FC 32 47 D5 8E 85 D4 1B F1 3E 4C DF 87 8D'),
# bytes.fromhex('B1 51 B8 2B 6F EB F8 82 AE 4F A5 37 74 F1 E1 9A'),
# bytes.fromhex('F5 CC D5 5F 2E D9 29 6D 69 0C A7 E8 BD 17 56 D6'),
# bytes.fromhex('E2 4F 07 CB 53 1E BF E0 3C F5 47 62 92 BA E2 55'),
# bytes.fromhex('10 96 89 73 E5 5A 5C 2C CB 83 75 41 A2 8F D2 A9'),
# bytes.fromhex('D5 8E BA 93 37 C1 BD 58 64 DF 02 B8 58 2A 45 DA'),
# bytes.fromhex('40 C3 6B 99 50 55 E2 EA B5 0F BE C6 7E 8C CB 87'),
# bytes.fromhex('D7 94 3F 47 02 1A 85 D4 35 DB 38 8C 51 04 3A 34'),
# bytes.fromhex('7B 1B DE 12 3B D8 B5 8B 6B 8D 57 61 DE 82 E9 A7'),
# bytes.fromhex('90 FE A5 E2 47 6A 9A A5 45 70 1F 71 70 AB 27 FD'),
# bytes.fromhex('6D AC 6E 3F 16 B7 B0 2D 2D 6F 05 A6 46 E2 52 C7')]
# isFFtoF0 = b'\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5\xF4\xF3\xF2\xF1\xF0'[::-1]
# is0toF = b'\x00\x01\x02\x03\x04\x05\x06\a\b\t\n\v\f\r\x0E\x0F'[::-1]
# is10to1F = b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F'[::-1]
# res = b''
# for i in range(0, len(data), 16):
#     v12 = data[i:i+16][::-1]
#     xmm0 = pxor(pxor(v12, isFFtoF0), is0toF)
#     xmm0 = aesenc(xmm0, is10to1F)
#     xmm0 = aesenc(xmm0, anon[0])
#     xmm0 = aesenc(xmm0, anon[1])
#     xmm0 = aesenc(xmm0, anon[2])
#     xmm0 = aesenc(xmm0, anon[3])
#     xmm0 = aesenc(xmm0, anon[4])
#     xmm0 = aesenc(xmm0, anon[5])
#     xmm0 = aesenc(xmm0, anon[6])
#     xmm0 = aesenc(xmm0, anon[7])
#     xmm0 = aesenc(xmm0, anon[8])
#     xmm0 = aesenc(xmm0, anon[9])
#     xmm0 = aesenc(xmm0, anon[10])
#     xmm0 = aesenc(xmm0, anon[11])
#     xmm0 = aesenclast(xmm0, anon[12])
#     res += xmm0[::-1]
#     isFFtoF0 = xmm0

# print(res.hex())