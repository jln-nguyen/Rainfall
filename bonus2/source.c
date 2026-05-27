#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int lang = 0; // 0x8049988 - variable globale

void greetuser(char *input)
{
    char buffer[72]; // -0x48(%ebp), frame de 0x58

    if (lang == 1)
    {
        // 0x8048717 - 19 octets
        strcpy(buffer, "Hyvää päivää ");
    }
    else if (lang == 2)
    {
        // 0x804872a - 14 octets
        strcpy(buffer, "Goedemiddag! ");
    }
    else
    {
        // 0x8048710 - 7 octets
        strcpy(buffer, "Hello ");
    }

    strcat(buffer, input); // VULNERABLE - pas de vérification de taille
    puts(buffer);
}

int main(int argc, char **argv)
{
    char buf[76];   // esp+0x50, 19 dwords (rep movsl)
    char *env;

    if (argc != 3)
        return 1;

    memset(buf, 0, 76);

    strncpy(buf,        argv[1], 40); // 0x28
    strncpy(buf + 40,   argv[2], 32); // 0x20, offset 0x28

    env = getenv("LANG");

    if (env != NULL)
    {
        if (memcmp(env, "fi", 2) == 0)
            lang = 1;
        else if (memcmp(env, "nl", 2) == 0)
            lang = 2;
    }

    // rep movsl : copie buf sur la stack de greetuser via l'argument
    greetuser(buf);

    return 0;
}