#include <stdio.h>
#include <stdlib.h>

void run()
{
    printf("Good... Wait what?\n");
    system("/bin/sh");
}

int main()
{
    char input[76];

    gets(input);
    return 0;
}
