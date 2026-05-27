void main() {
    char dest[54];
    pp(dest);
    puts(dest);
}

void pp(char *dest) {
    char input1[20];
    char input2[20];

    p(input1, "prompt");   // lit stdin → strncpy 20 bytes dans input1
    p(input2, "prompt");   // lit stdin → strncpy 20 bytes dans input2

    strcpy(dest, input1);  // copie input1 dans dest (pas de vérification taille !)

    int len = strlen(dest);
    dest[len]     = ' ';   // ajoute un espace après input1
    dest[len + 1] = '\0';

    strcat(dest, input2);  // concatène input2 (pas de vérification taille !)
}

void p(char *dest, char *prompt) {
    char buffer[4096];     // grand buffer temporaire sur la stack

    puts(prompt);
    read(0, buffer, 4096); // lit jusqu'à 4096 octets depuis stdin

    char *newline = strchr(buffer, '\n');
    *newline = '\0';       // remplace '\n' par '\0'

    strncpy(dest, buffer, 20); // copie seulement 20 octets vers dest
                               // le reste du buffer RESTE en mémoire !
}