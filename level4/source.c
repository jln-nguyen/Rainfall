#include <stdio.h>
#include <stdlib.h>

int secret = 0;

void p(char *input)
{
    printf(input);
}

void n()
{
    char input[520];

    fgets(input, 512, stdin);
    p(input);

    if (secret == 16930116) 
        system("/bin/cat /home/user/level5/.pass");
}

int main()
{
    n();
    return 0;
}
