#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void n()
{
    system("/bin/cat /home/user/level7/.pass");
}

void m()
{
    puts("Nope");
}

int main(int argc, char **argv)
{
    char    *heap_buf;
    void    (**func_ptr)();

    heap_buf = malloc(64);
    func_ptr = malloc(4);

    *func_ptr = m;

    strcpy(heap_buf, argv[1]);

    (*func_ptr)();

    return 0;
}
