#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv)
{
    int t;
    char timestr[32];
    int len = 0;

    if (argc < 2) {
        printf("Invaild args.");
        exit(0);
    }

    t = atoi(argv[1]);
    strftime(timestr, 32, "%Y-%m-%d %H:%M:%S",
            localtime((time_t *)&t));

    printf("%s\n", timestr);
    return 0;
}
