f = open("flag.txt.enc", "rb")

byte = f.read()
byte = list(byte)
for i in range(len(byte)):
    if i % 10 == 9: print(f'0x{byte[i]:02X}', end = ',\n')
    else: print(f'0x{byte[i]:02X}', end = ', ')