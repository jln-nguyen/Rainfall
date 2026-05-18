#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char    buf[40];        // local buffer at esp+0x14
    int     n;              // control variable at esp+0x3c

    n = atoi(argv[1]);

    if (n > 9)              // signed check — negative values pass
        return 1;

    memcpy(buf, argv[2], n * 4);  // size is cast to size_t (unsigned!)
                                  // -2147483637 * 4 wraps to 44 bytes
                                  // → overwrites buf AND n itself

    if (n == 0x574f4c46)   // "FLOW" in little-endian ASCII
        execl("/bin/sh", "/bin/sh", NULL);

    return 0;
}
