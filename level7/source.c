#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char g_password[68];

void m()
{
    printf("%s - %d\n", g_password, time(0));
}

int main(int argc, char **argv)
{
    int **chunk1 = malloc(8);
    chunk1[0] = (int *)1;
    chunk1[1] = (int *)malloc(8);

    int **chunk2 = malloc(8);
    chunk2[0] = (int *)2;
    chunk2[1] = (int *)malloc(8);

    strcpy((char *)chunk1[1], argv[1]);
    strcpy((char *)chunk2[1], argv[2]);

    FILE *file = fopen("/home/user/level8/.pass", "r");
    fgets(g_password, 68, file);

    puts("~~");

    return 0;
}
