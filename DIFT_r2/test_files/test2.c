//#include <stdio.h>
#include <unistd.h>
int main(void)
{
    char str[7] = {'H','E','L','L','O','\n','\0'};
    //puts(str);
    write(1,str,6);
    return 0;
}
