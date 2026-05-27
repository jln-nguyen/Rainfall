#include <stdio.h>
#include <string.h>
#include <unistd.h>

void p(char *dest, char *prompt)
{
    char read_buf[4096];

    puts(prompt);
    read(0, read_buf, 4096);

    char *newline = strchr(read_buf, '\n');
    *newline = '\0';

    strncpy(dest, read_buf, 20);
}

void pp(char *result)
{
    char input1[20];
    char input2[20];

    p(input1, " - ");
    p(input2, " - ");

    strcpy(result, input1);

    int len = strlen(result);
    result[len]     = ' ';
    result[len + 1] = '\0';

    strcat(result, input2);
}

int main()
{
    char result[54];

    pp(result);
    puts(result);
    return 0;
}
