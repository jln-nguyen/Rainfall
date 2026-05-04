#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

int setresuid(uid_t ruid, uid_t euid, uid_t suid);
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);

int main(int ac, char **av)
{
	int nb = atoi(av[1]);
	char *arg[2]; 
	if (nb != 423)
		printf("No !\n");
	else
	{
		gid_t	gid = getegid();
		uid_t	uid = geteuid();
		setresgid(gid, gid, gid);
		setresuid(uid, uid, uid);
		arg[0] = strdup("/bin/sh");
		arg[1] = NULL;
		execv("/bin/sh", arg);
	}
	return 0;
}