#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *auth = NULL;
char *service = NULL;

int main(void)
{
    char buffer[128];

    while (1)
    {
        printf("%p, %p \n", auth, service);

        if (fgets(buffer, 128, stdin) == NULL)
            return 0;

        // Commande "auth "
        if (strncmp(buffer, "auth ", 5) == 0)
        {
            auth = malloc(4);
            memset(auth, 0, 4);

            char *str = buffer + 5;
            if (strlen(str) < 31)
                strcpy(auth, str);
        }

        // Commande "reset"
        if (strncmp(buffer, "reset", 5) == 0)
        {
            free(auth);
        }

        // Commande "service"
        if (strncmp(buffer, "service", 7) == 0)
        {
            service = strdup(buffer + 8);
        }

        // Commande "login"
        if (strncmp(buffer, "login", 5) == 0)
        {
            if (*(int *)(auth + 0x20) == 0)
                fwrite("Password:\n", 1, 10, stdout);
            else
                system("/bin/sh");
        }
    }

    return 0;
}