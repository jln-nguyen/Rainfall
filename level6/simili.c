#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void n(void)
{
    system("/bin/cat /home/user/level7/.pass");
}

void m(void)
{
    puts("Nope");
}

int main(int argc, char **argv)
{
    char    *buf;       // esp+0x1c
    void    (**fptr)(); // esp+0x18

    buf  = malloc(0x40);           // malloc(64)
    fptr = malloc(0x4);            // malloc(4)

    *fptr = m;                     // stocke l'adresse de m() dans le pointeur

    strcpy(buf, argv[1]);          // copie argv[1] dans buf → overflow possible

    (*fptr)();                     // appelle la fonction pointée (m par défaut, n si overflow)

    return 0;
}
