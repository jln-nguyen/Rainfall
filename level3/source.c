#include <stdio.h>
#include <stdlib.h>

int m = 0;

void v()
{
    char input[536];

    fgets(input, 536, stdin);
    printf(input);
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
