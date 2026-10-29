#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

int main(int argc, char **argv)
{
    void *ptr;

    (void)argc;

    /* 1. Memory violation: RWX anonymous mapping */
    ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /* 2. Disk violation: unlink executable binary while running */
    if (argv[0] != NULL) {
        unlink(argv[0]);
    }

    printf("[ROGUE] PID %ld running with deleted binary and RWX memory.\n", (long)getpid());
    fflush(stdout);

    /* Stay alive for 20 seconds so proc-sentry can audit it */
    sleep(20);

    munmap(ptr, 4096);
    return 0;
}
