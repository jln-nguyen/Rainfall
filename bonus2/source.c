#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int lang = 0;

void greetuser(char *input)
{
    char greeting[72];

    if (lang == 1)
        strcpy(greeting, "Hyvää päivää ");
    else if (lang == 2)
        strcpy(greeting, "Goedemiddag! ");
    else
        strcpy(greeting, "Hello ");

    strcat(greeting, input);
    puts(greeting);
}

int main(int argc, char **argv)
{
    char    combined_buf[76];
    char    *lang_env;

    if (argc != 3)
        return 1;

    memset(combined_buf, 0, 76);

    strncpy(combined_buf,      argv[1], 40);
    strncpy(combined_buf + 40, argv[2], 32);

    lang_env = getenv("LANG");

    if (lang_env != NULL)
    {
        if (memcmp(lang_env, "fi", 2) == 0)
            lang = 1;
        else if (memcmp(lang_env, "nl", 2) == 0)
            lang = 2;
    }

    greetuser(combined_buf);
    return 0;
}
