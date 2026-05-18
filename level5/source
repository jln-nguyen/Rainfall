// Reconstructed C — level5 (RainFall)
// Compiled as 32-bit, no stack canary, NX enabled

#include <stdio.h>
#include <stdlib.h>

// Never called directly — the target
// Called via GOT overwrite when exit() is redirected here
void o(void)
{
    system("/bin/sh");  // 0x80485f0 = "/bin/sh"
    _exit(1);
}

// Vulnerable function
void n(void)
{
    char buf[520];  // 0x208 bytes on stack (ebp - 0x208)

    fgets(buf, 512, stdin);  // safe read — no overflow here

    printf(buf);             // !! FORMAT STRING VULN !!
                             // buf is used directly as format string
                             // → attacker controls %x %n %hn etc.

    exit(1);                 // target of GOT overwrite
                             // after overwrite: jumps to o() instead
}

int main(void)
{
    n();
    return 0;
}
