#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

/*
 *This is a test file for MINOS DIFT
 *Make sure to compile with -fno-stack-protector:
 *gcc buff_overflow.c -Wall -Werror -fno-stack-protector -m32 -g
 * */
int main (void)
{
    int i = 0;
    char ov[3];
    ov[0] = 'z';
    ov[1] = 'x';
    ov[2] = 'y';
    char hs[2000];
    char *hsp = hs;
    char *ovp = ov;
    int fd = open("HI2", O_RDONLY);
    read(fd, hsp++, 1);
    for (i = 0; i < 2000; i++) {
        //putchar(*(hsp -1 ));
        read(fd, hsp++, 1);
    }
    for (i = 0; hs[i] != 'q'; i++) {
        *(ovp + i) = hs[i] + 2;
        if (i == 3) {
            i += 40;
        }
    }
    write(1, ov, 6);
    return 0;
}
