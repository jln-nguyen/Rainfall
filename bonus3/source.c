#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char    password[65];
    char    remainder[66];
    FILE    *file;
    int     trunc_pos;

    if (argc != 2)
        return -1;

    file = fopen("/home/user/end/.pass", "r");
    if (file == NULL)
        return -1;

    memset(password, 0, sizeof(password));
    fread(password, 1, 66, file);
    password[66] = '\0';

    trunc_pos = atoi(argv[1]);
    password[trunc_pos] = '\0';

    fread(remainder, 1, 65, file);
    fclose(file);

    if (strcmp(password, argv[1]) == 0)
        execl("/bin/sh", "sh", NULL);
    else
        puts(remainder);

    return 0;
}
