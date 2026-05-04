#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void p() {
    char buffer[76];         // sub $0x68,%esp → 104o alloués, buffer à ebp-0x4c = 76o
    void *ret_addr;

    fflush(stdout);

    gets(buffer);            // pas de limite -> overflow

    // récupère la return address depuis la stack
    ret_addr = __builtin_return_address(0);

    // protection anti-stack : bloque les adresses 0xbf......
    if (((unsigned int)ret_addr & 0xb0000000) == 0xb0000000) {
        printf("(%p)\n", ret_addr);
        _exit(1);
    }

    puts(buffer);
    strdup(buffer);          // copie sur le heap → adresse 0x0804xxxx, passe la protection
}

int main() {
    p();
    return 0;
}
