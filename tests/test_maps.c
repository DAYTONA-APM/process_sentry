#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "maps_audit.h"

int main(void)
{
    void *ptr;
    size_t size;
    int mask;

    size = 4096; /* 1 page */

    printf("[*] Allocating RWX anonymous memory page...\n");

    /* Allocate readable, writable, executable anonymous memory */
    ptr = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (ptr == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("[*] Running maps audit on PID %ld...\n", (long)getpid());
    mask = audit_process_maps(getpid());

    if (mask < 0) {
        fprintf(stderr, "FAIL: audit_process_maps encountered an error\n");
        munmap(ptr, size);
        return 1;
    }

    /* Assert ANOMALY_RWX */
    if (mask & ANOMALY_RWX) {
        printf("PASS: Caught ANOMALY_RWX violation\n");
    } else {
        fprintf(stderr, "FAIL: Expected ANOMALY_RWX flag not set\n");
    }

    /* Assert ANOMALY_ANON_EXEC */
    if (mask & ANOMALY_ANON_EXEC) {
        printf("PASS: Caught ANOMALY_ANON_EXEC violation\n");
    } else {
        fprintf(stderr, "FAIL: Expected ANOMALY_ANON_EXEC flag not set\n");
    }

    /* Clean up fixture memory */
    munmap(ptr, size);

    if ((mask & ANOMALY_RWX) && (mask & ANOMALY_ANON_EXEC)) {
        printf("[+] All Stage 3 memory audit checks passed.\n");
        return 0;
    }

    return 1;
}
