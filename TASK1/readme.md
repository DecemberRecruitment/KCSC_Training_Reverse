# TASK 1

## Nhiệm vụ

```txt
Code thuật toán mã hóa RC4 bằng masm
Yêu cầu: -  Chạy được và phải đúng
         -  Input: Plain Text + Key
         -  Output: Hex 
         -  Giải thích comment code rõ ràng
         -  RC4 gồm nhiều phase khác nhau, phải tìm hiểu và triển khai các phase đó ở dạng hàm
         -  Không được dùng các thư viện có sẵn (print hex, kể cả kernel32.dll để gọi API,...) 
         -  Bài này chỉ sử dụng 4 WinAPI là GetStdHandle, WriteConsole, ReadConsole và ExitProcess
         -  Sử dụng PEB để resolve 4 A1PI trên
Suggested IDE: https://www.masm32.com/
```

## Code

[pebRC4.asm](CODE/pebRC4.asm)

[pebRC4.exe](CODE/pebRC4.exe)

[pebRC4.obj](CODE/pebRC4.obj)

## Demo

![alt text](IMG/image.png)

