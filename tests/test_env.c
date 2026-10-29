#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "env_audit.h"

int main(int argc, char **argv)
{
    pid_t pid;
    int mask;

    /* If invoked with "--child-target", sleep briefly to let the parent audit it */
    if (argc > 1 && argv[1] != NULL) {
        pause();
        return 0;
    }

    printf("[*] Testing clean environment audit on PID %ld...\n", (long)getpid());
    mask = audit_process_env(getpid());
    if (mask < 0) {
        fprintf(stderr, "FAIL: Could not read /proc/self/environ\n");
        return 1;
    }
    printf("PASS: Clean scan returned mask: 0x%x\n", mask);

    printf("[*] Spawning child process with injected initial LD_PRELOAD...\n");
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /*
         * Child: execle replaces process image, ensuring the kernel sets
         * mm->env_start / mm->env_end in /proc/[pid]/environ with this array.
         */
        char *custom_env[] = {
            "PATH=/usr/bin:/bin",
            "USER=root",
            "LD_PRELOAD=/tmp/fake_malicious_hook.so",
            NULL
        };

        execle(argv[0], argv[0], "--child-target", (char *)NULL, custom_env);
        perror("execle");
        _exit(1);
    }

    /* Parent: Give child a second to exec */
    sleep(1);

    mask = audit_process_env(pid);
    if (mask < 0) {
        fprintf(stderr, "FAIL: Could not read /proc/%ld/environ\n", (long)pid);
        kill(pid, 9);
        waitpid(pid, NULL, 0);
        return 1;
    }

    /* Terminate child */
    kill(pid, 9);
    waitpid(pid, NULL, 0);

    if (mask & ENV_ANOMALY_PRELOAD) {
        printf("PASS: Successfully caught ENV_ANOMALY_PRELOAD on child PID %ld (mask: 0x%x)\n",
               (long)pid, mask);
        printf("[+] All Stage 5 environment audit checks passed.\n");
        return 0;
    }

    fprintf(stderr, "FAIL: Expected ENV_ANOMALY_PRELOAD flag not set (mask=0x%x)\n", mask);
    return 1;
}
