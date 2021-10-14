#include <stdio.h>
#include <stdlib.h>

char *strreplace(char *s, char _old, char _new)
{
    for (; *s; ++s)
        if (*s == _old)
            *s = _new;
    return s;
}

int main(int argc, char **argv)
{
    char *ptr;
    char buf[BUFSIZ] = {0};

    if (argc < 2) {
        exit(1);
    }

    snprintf(buf, BUFSIZ, "%s", argv[1]);

    strreplace(buf, '-', '.');
    printf("%s\n", buf);
}
