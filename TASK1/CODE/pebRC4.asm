.386 
.model flat, stdcall 
.stack 4096
assume fs:nothing

.data
    msg1 db "Key: ", 0
    msg1_len dd $-msg1
    msg2 db "Plaintext: ", 0
    msg2_len dd $-msg2
    msg3 db "Ciphertext: ", 0
    msg3_len dd $-msg3
    hex db "0123456789ABCDEF", 0
    hex_len dd $-hex
    sbox db 256 dup (1)
    bytesRead dd 0
    bytesWritten dd 0

.data?
    hStdIn dd ?
    hStdOut dd ?
    key db 256 dup (?)
    key_len dd ?
    cipher db 256 dup (?)
    cipher_len dd ?
    ans db 512 dup (?)
    ans_len dd ?

.code 
	main proc
        call getHandle
        call getKey
        call getCipher

        push key_len
        push offset key
        push offset sbox
        call creat_sbox         ; (sbox, key, key_len)

        push cipher_len
        push offset cipher
        push offset sbox
        call RC4_en             ; (sbox, cipher, cipher_len)

        push offset hex
        push cipher_len
        push offset cipher
        push ans_len
        push offset ans
        call hexToStr           ; (ans, ans_len, cipher, cipher_len, hex)

        push offset ans
        push ans_len
        call print_ans          ; (ans_len, ans)

		call ExitProcess
        push 0
        call eax
	main endp

	get_address proc
		; hình thành khung ngăn xếp mới
		push ebp
		mov ebp, esp

		; phân bổ các biến cục bộ và khởi tạo chúng về 0
		sub esp, 1ch
		xor eax, eax
		mov [ebp - 04h], eax			; nơi sẽ lưu số lượng hàm có trong kernel32.dll
		mov [ebp - 08h], eax			; nơi sẽ lưu địa chỉ của Exported Functions Table (bảng chứa địa chỉ của các hàm trong kernel32.dll)
		mov [ebp - 0ch], eax			; nơi sẽ lưu địa chỉ của Name Pointer Table
		mov [ebp - 10h], eax			; nơi sẽ lưu địa chỉ của Functions Ordinal Table
		mov [ebp - 14h], eax			; nơi sẽ lưu chuỗi ký tự dạng null-terminated cho "WinExec"
		mov [ebp - 18h], eax			; nơi sẽ lưu địa chỉ của hàm WinExec
		mov [ebp - 1ch], eax			; để dành (reserved) cho mục đích khác

		; đẩy WinExec vào ngăn xếp và lưu nó vào một biến cục bộ
		mov [ebp - 14h], esi			; lưu trữ con trỏ tới WinExec

		;  lấy địa chỉ kernel32.dll
		mov eax, [fs:30h]		    	; con trỏ tới PEB (https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)
		mov eax, [eax + 0ch]			; con trỏ tới Ldr
		mov eax, [eax + 14h]			; con trỏ tới InMemoryOrderModuleList
		mov eax, [eax]				  	; module của chương trình này
		mov eax, [eax]  				; ntdll module
		mov eax, [eax - 8h + 18h]		; kernel32.DllBase

		; địa chỉ kernel32.dll
		mov ebx, eax					; lưu trữ địa chỉ kernel32.dll vào ebx

		; lấy địa chỉ của PE signature
		mov eax, [ebx + 3ch]			; Lấy giá trị tại offset 0x3C từ địa chỉ trong ebx, đây là RVA của PE signature
		add eax, ebx				    ; Cộng giá trị này với địa chỉ cơ sở của kernel32 (ebx), để eax trở thành địa chỉ PE signature: eax = 0xf8 + kernel32 base

		; lấy địa chỉ của Export Table
		mov eax, [eax + 78h]			; 0x78 bytes sau PE signature là RVA của Export Table
		add eax, ebx					; địa chỉ của Export Table = Export Table RVA + kernel32 base

		; lấy số lượng hàm có trong kernel32.dll
		mov ecx, [eax + 14h]			; chứa giá trị biểu thị số lượng hàm của kernel32.dll
		mov [ebp - 4h], ecx				; Lưu lại gía trị số lượng hàm trong kernel32.dll

		; lấy địa chỉ của bảng Exported Functions Table (chứa các tất cả địa chỉ của hàm trong kernel32.dll)
		mov ecx, [eax + 1ch]			; lấy RVA của Exported Functions Table
		add ecx, ebx				    ; lấy địa chỉ của Exported Functions Table
		mov [ebp - 8h], ecx				; lưu lại địa chỉ của Exported Functions Table

		; lấy địa chỉ của Name Pointer Table (bảng chứa các giá trị RVA mà chương trình cần khi thực thi mà sử dụng từ thư viện ngoài, trong TH này là kernel32.dll)
		mov ecx, [eax + 20h]			; lấy RVA của Name Pointer Table
		add ecx, ebx					; lấy địa chỉ của Name Pointer Table
		mov [ebp - 0ch], ecx			; lưu lại đia chỉ của Name Pointer Table

		; lấy địa chỉ của Functions Ordinal Table
		mov ecx, [eax + 24h]			; lấy RVA của Functions Ordinal Table
		add ecx, ebx					; Lấy địa chỉ của Functions Ordinal Table
		mov [ebp - 10h], ecx			; lưu lại địa chỉ của Functions Ordinal Table
	
		; loop through exported function name pointer table and find position of WinExec
		xor eax, eax
		xor ecx, ecx
			
		findWinExecPosition:
			mov esi, [ebp - 14h]		; esi = con trỏ tới WinExec
			mov edi, [ebp - 0ch]		; edi = con trỏ tới Name Pointer Table
			cld							; https://en.wikipedia.org/wiki/Direction_flag
			mov edi, [edi + eax*4]		; Lấy giá trị RVA hàm trong bảng Name Pointer Table
			add edi, ebx				; Lấy địa chỉ của tên hàm đó 

			mov cx, 8					; yêu cầu lệnh so sánh tiếp theo để so sánh 8 byte đầu tiên
			repe cmpsb					; check nếu esi = edi
				
			jz FunctionFound
			inc eax						; tăng biến đếm
			cmp eax, [ebp - 4h]			; check biến đếm với giá trị tất cả các hàm có trong kernel32.dll
			jne findWinExecPosition

		FunctionFound:
			mov ecx, [ebp - 10h]		; ecx = Functions Ordinal Table
			mov edx, [ebp - 8h]			; edx = Exported Functions Table

			; get address of WinExec ordinal
			mov ax, [ecx + eax * 2]		; lấy thứ tự của hàm WinExec trong Functions Ordinal Table
			mov eax, [edx + eax * 4]	; lấy RVA của hàm WinExec trong Functions Ordinal Table
			add eax, ebx				; Lấy địa chỉ của hàm WinExec
		add esp, 1Ch
		pop ebp
		ret
	get_address endp

	ExitProcess proc
		push ebp
		mov ebp, esp
		push 00737365h                  ; null,s,s,e
		push 636f7250h                  ; đẩy c,o,r,P
		push 74697845h                  ; đẩy t,i,x,E
		mov esi, esp                    ; chuyển địa chỉ chuỗi "ExitProcess" vào thanh esi
		call get_address                ; lấy địa chỉ của hàm "ExitProcess", kết quả trả về thanh eax
		add esp, 0ch                    ; do trong hàm này mình đã push các kí tự vô stack nên muốn trở lại
		ret                             ;       đúng vị trí chuẩn ban đầu của stack ta cần dịch lại vị trí
		pop ebp
	ExitProcess endp

	GetStdHandle proc
		push ebp
		mov ebp, esp
		push 0041h                      ; đẩy null,A
		push 656c646eh                  ; đẩy e,l,d,n
		push 61486474h                  ; đẩy a,H,d,t
		push 53746547h                  ; đẩy S,t,e,G
		mov esi, esp                    ; chuyển địa chỉ chuỗi "GetStdHandleA" vào thanh esi
		call get_address                ; lấy địa chỉ của hàm "GetStdHandleA", kết quả trả về thanh eax
		add esp, 10h                    ; do trong hàm này mình đã push các kí tự vô stack nên muốn trở lại
		pop ebp                         ;       đúng vị trí chuẩn ban đầu của stack ta cần dịch lại vị trí
		ret
	GetStdHandle endp

	WriteConsoleA proc
		push ebp
		mov ebp, esp
		push 0041h                      ; đẩy null,A            
		push 656c6f73h                  ; đẩy e,l,o,s
		push 6e6f4365h                  ; đẩy n,o,C,e
		push 74697257h                  ; đẩy t,i,r,W
		mov esi, esp                    ; chuyển địa chỉ chuỗi "WriteConsoleA" vào thanh esi
		call get_address                ; lấy địa chỉ của hàm "GetStdHandleA", kết quả trả về thanh eax
		add esp, 10h                    ; do trong hàm này mình đã push các kí tự vô stack nên muốn trở lại
		pop ebp                         ;       đúng vị trí chuẩn ban đầu của stack ta cần dịch lại vị trí
		ret
	WriteConsoleA endp

	ReadConsoleA proc
		push ebp
		mov ebp, esp
		push 0h                 ; đẩy null
		push 41656c6fh          ; đẩy A,e,l,o
		push 736e6f43h          ; đẩy s,n,o,C
		push 64616552h          ; đẩy d,a,e,R
		mov esi, esp            ; chuyển địa chỉ chuỗi "ReadConsoleA" vào thanh esi
		call get_address        ; lấy địa chỉ của hàm "ReadConsoleA", kết quả trả về thanh eax
		add esp, 10h            ; do trong hàm này mình đã push các kí tự vô stack nên muốn trở lại
		pop ebp                 ;       đúng vị trí chuẩn ban đầu của stack ta cần dịch lại vị trí
		ret
	ReadConsoleA endp

    print_ans proc
        push ebp
        mov ebp, esp

		call WriteConsoleA      ; eax = WriteConsoleA
        push 0                  ; lpReserved
        push offset bytesWritten; lpNumberOfCharsWritten
        push msg3_len           ; nNumberOfCharsToWrite
        push offset msg3        ; *lpBuffer
        push hStdOut            ; hConsoleOutput
        call eax

		call WriteConsoleA      ; eax = WriteConsoleA
        push 0                  ; lpReserved
        push offset bytesWritten; lpNumberOfCharsWritten
        push ans_len            ; nNumberOfCharsToWrite
        push offset ans         ; *lpBuffer
        push hStdOut            ; hConsoleOutput
        call eax

        pop ebp
        ret
    print_ans endp

    ; [ebp+8]     ans
    ; [ebp+12]    ans_len
    ; [ebp+16]    cipher
    ; [ebp+20]    cipher_len
    ; [ebp+24]    hex
    hexToStr proc
        push ebp
        mov ebp, esp

        xor esi, esi    ; esi = i
        L4:
            mov edi, [ebp+16]
            xor eax, eax
            mov al, [edi+esi]   ; al = cipher[i]
            xor ebx, ebx
            mov bl, 16
            div bl              ; ah = /, al = %
            mov edi, [ebp+24]   ; hex
            xor ebx, ebx
            mov bl, al          ; bl = al
            mov bl, [edi+ebx]   ; ebx = hex[?]
            mov edi, [ebp+8]    ; ans
            mov byte ptr [edi+2*esi], bl
            mov edi, [ebp+24]
            mov bl, ah
            mov bl, [edi+ebx]   ; ebx = hex[?]
            mov edi, [ebp+8]
            mov byte ptr [edi+2*esi+1], bl
            inc esi
            cmp esi, [ebp+20]
            jl L4
        xor eax, eax
        mov edi, [ebp+20]
        add edi, edi
        mov ans_len, edi
        pop ebp
        ret
    hexToStr endp

    ; [ebp+8]   sbox
    ; [ebp+12]  key
    ; [ebp+16]  key_len
    creat_sbox proc
        push ebp
        mov ebp, esp

        mov eax, [ebp+8]        ; sbox
        xor edx, edx
        L1:
            mov [eax + edx], dl
            add edx, 1
            cmp edx, 256
            jl L1

        mov ecx, [ebp+8]                            ; ecx = sbox    j = (j + map[i] + key[i % len(key)]) % 256
        xor edx, edx                                ; i
        xor esi, esi                                ; j

        L2: 
            xor ebx, ebx
            mov eax, [ebp + 8]  ; eax = sbox
            mov bl, [eax+edx]   ; bl = sbox[i]
            add esi, ebx        ; esi = j + sbox[i]
            xor eax, eax            

            mov eax, edx        ; eax = i
            mov ebx, [ebp+16]   ; ebx = key_len
            div bl              ; ah = /, al = %, i % key_len

            xor ebx, ebx
            mov bl, ah          ; ebx = i % key_len

            xor ecx, ecx
            mov eax, [ebp+12]
            mov cl, [eax+ebx]
            add esi, ecx
            and esi, 0FFh ; esi = (j + map[i] + key[i % len(key)]) % 256

            mov ebx, [ebp+8]    ; sbox
            xor eax, eax
            mov al, [ebx+edx]   ; al = sbox[i]
            mov ah, [ebx+esi]   ; ah = sbox[j]
            mov byte ptr [ebx+edx], ah
            mov byte ptr [ebx+esi], al

            inc edx
            cmp edx, 0FFh
            jle L2
        pop ebp
        ret
    creat_sbox endp 

    ; [ebp+8]   sbox
    ; [ebp+12]  cipher
    ; [ebp+16]  cipher_len
    RC4_en proc
        push ebp
        mov ebp, esp

        xor esi, esi    ; n
        xor edi, edi    ; m
        xor edx, edx    ; i
        
        L3:
            inc esi
            and esi, 0FFh       ; (n + 1) % 256       -----

            mov eax, [ebp+8]    ; sbox
            xor ebx, ebx
            mov bl, [eax+esi]   ; sbox[n]
            add edi, ebx        ; m + sbox[n]
            and edi, 0FFh       ; (m + sbox[n]) % 256 -----

            xor ebx, ebx
            mov eax, [ebp+8]
            mov bl, [eax+esi]   ; bl = map[n]
            mov bh, [eax+edi]   ; bh = map[m]
            mov byte ptr [eax+esi], bh
            mov byte ptr [eax+edi], bl

            xor eax, eax
            xor ecx, ecx
            mov cl, bl
            add eax, ecx
            mov cl, bh
            add eax, ecx
            and eax, 0FFh       ; eax = (map[n] + map[m]) % 256
            mov ebx, [ebp+8]
            xor ecx, ecx
            mov cl, [ebx+eax]   ; cl = map[(map[n] + map[m]) % 256]

            mov ebx, [ebp+12]   ; cipher
            xor eax, eax
            mov al, [ebx+edx]   ; cipher[i]
            xor al, cl
            mov [ebx+edx], al   ;
            xor eax, eax
            mov eax, [ebp+16]

            inc edx
            cmp edx, eax
            jl L3
        pop ebp
        ret
    RC4_en endp

    getHandle proc
        push ebp
        mov ebp, esp
        ; Lấy handle Output
        call GetStdHandle       ; eax = GetStdHandle
        push -11                ; STD_OUTPUT_HANDLE
		call eax                
        mov hStdOut, eax        
        ; Lấy handle Input
        call GetStdHandle       ; eax = GetStdHandle
        push -10                ; STD_INPUT_HANDLE 
		call eax
        mov hStdIn, eax
        pop ebp
        ret
    getHandle endp

    getKey proc
        push ebp
        mov ebp, esp
        ; In ra "Key: "
		call WriteConsoleA      
        push 0
        push offset bytesWritten
        push msg1_len
        push offset msg1
        push hStdOut            
        call eax
        ; Nhập key
		call ReadConsoleA
        push 0
        push offset bytesRead
        push 256
        push offset key
        push hStdIn
        call eax
        ; Lấy chiều dài của Key
        mov eax, bytesRead
        sub eax, 2
        mov key_len, eax

        pop ebp
        ret
    getKey endp

    getCipher proc
        push ebp
        mov ebp, esp

        ; Hiện "Cipher Text: "
		call WriteConsoleA
        push 0
        push offset bytesWritten
        push msg2_len
        push offset msg2
        push hStdOut
        call eax
        ; Nhập Cipher Text
		call ReadConsoleA
        push 0
        push offset bytesRead
        push 256
        push offset cipher
        push hStdIn
        call eax
        ; Lấy chiều dài của CipherText
        mov eax, bytesRead
        sub eax, 2
        mov cipher_len, eax

        pop ebp
        ret
    getCipher endp

	end main