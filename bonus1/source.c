#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char    copy_buf[40];
    int     count;

    count = atoi(argv[1]);

    if (count < 10)
    {
        memcpy(copy_buf, argv[2], count * 4);

        if (count == 0x574f4c46)
            execl("/bin/sh", "sh", NULL);

        return 0;
    }
    return 1;
}
