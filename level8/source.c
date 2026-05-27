#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *auth    = NULL;
char *service = NULL;

int main(void)
{
    char cmd_buf[128];

    while (1)
    {
        printf("%p, %p \n", auth, service);

        if (fgets(cmd_buf, 128, stdin) == NULL)
            return 0;

        if (strncmp(cmd_buf, "auth ", 5) == 0)
        {
            auth = malloc(4);
            memset(auth, 0, 4);
            if (strlen(cmd_buf + 5) < 31)
                strcpy(auth, cmd_buf + 5);
        }

        if (strncmp(cmd_buf, "reset", 5) == 0)
            free(auth);

        if (strncmp(cmd_buf, "service", 7) == 0)
            service = strdup(cmd_buf + 8);

        if (strncmp(cmd_buf, "login", 5) == 0)
        {
            if (*(int *)(auth + 0x20) == 0)
                fwrite("Password:\n", 1, 10, stdout);
            else
                system("/bin/sh");
        }
    }
    return 0;
}
