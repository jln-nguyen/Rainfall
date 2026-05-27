#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

int main(int argc, char **argv)
{
    int     user_input = atoi(argv[1]);
    char    *shell_args[2];

    if (user_input != 423)
    {
        printf("No !\n");
    }
    else
    {
        gid_t gid = getegid();
        uid_t uid = geteuid();
        setresgid(gid, gid, gid);
        setresuid(uid, uid, uid);
        shell_args[0] = strdup("/bin/sh");
        shell_args[1] = NULL;
        execv("/bin/sh", shell_args);
    }
    return 0;
}
