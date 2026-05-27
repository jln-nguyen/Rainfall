#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void p()
{
    char    input[76];
    void    *ret_addr;

    fflush(stdout);
    gets(input);

    ret_addr = __builtin_return_address(0);

    if (((unsigned int)ret_addr & 0xb0000000) == 0xb0000000)
    {
        printf("(%p)\n", ret_addr);
        _exit(1);
    }

    puts(input);
    strdup(input);
}

int main()
{
    p();
    return 0;
}
