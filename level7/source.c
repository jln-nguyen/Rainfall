#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Buffer global où le mot de passe est stocké (adresse 0x8049960)
char g_password[68];  // 0x44 = 68 bytes

void m(void)
{
    printf("%s - %d\n", g_password, time(0));
}

int main(int argc, char **argv)
{
    // Struct 1
    int **s1 = malloc(8);   // {int tag, char* buf}
    s1[0] = (int *)1;       // tag = 1
    s1[1] = (int *)malloc(8); // buffer de données

    // Struct 2
    int **s2 = malloc(8);   // {int tag, char* buf}
    s2[0] = (int *)2;       // tag = 2
    s2[1] = (int *)malloc(8); // buffer de données

    strcpy((char *)s1[1], argv[1]);  // overflow possible ici → écrase s2[1]
    strcpy((char *)s2[1], argv[2]);  // écrit à l'adresse contenue dans s2[1]

    FILE *f = fopen("/home/user/level8/.pass", "r");
    fgets(g_password, 0x44, f);

    puts("~~");  // ← en réalité après exploit, saute vers m()

    return 0;
}