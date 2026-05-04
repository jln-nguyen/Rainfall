#include <stdio.h>
#include <stdlib.h>

int m;

void    v()
{
    char buf[536];
    fgets(buf, 536, stdin);
    printf(buf);
    if (m == 64)
    {
        fwrite("Wait what?!\n", sizeof(char), 12, stdout);
        system("/bin/sh");
    }
}

int main()
{
    v();
    return 0;
}