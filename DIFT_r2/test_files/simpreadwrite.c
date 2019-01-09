#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
/*
 *Make sure to compile with/wo:
 *-m32, -static
 * */
int main (void)
{
    char hs[6];
    char rs[6];
    hs[5] = '\0';
    int fd = open("HI", O_RDONLY);
    read(fd, hs, 5);
    for (int i = 0; i < 6; i++) {
        rs[i] = hs[i];
    }
    write(1, rs, 6);
    return 0;
}
