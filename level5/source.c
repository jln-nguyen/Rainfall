#include <stdlib.h>
#include <stdio.h>

void o()
{
    system("/bin/sh");
    exit(1);
}

void n()
{
    char input[536];

    fgets(input, 536, stdin);
    printf(input);
    exit(1);
}

int main()
{
    n();
    return 0;
}
