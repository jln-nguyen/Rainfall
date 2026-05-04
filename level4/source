#include <stdio.h>
#include <stdlib.h>

// Variable globale @ 0x8049810
int secret = 0;

void p(char *buf) {
    printf(buf); 
}

void n() {
    char buf[520];

    fgets(buf, 512, stdin);
    p(buf);

    if (secret == 16930116) {
        system("/bin/cat /home/user/level5/.pass");
    }
}

int main() {
    n();
    return 0;
}
