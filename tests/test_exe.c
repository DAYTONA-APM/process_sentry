#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

#include "exe_audit.h"

static void test_normal_process(void)
{
    char path[PATH_MAX];
    pid_t self;
    int status;

    printf("[*] Testing normal process exe audit...\n");
    self = getpid();
    status = audit_process_exe(self, path, sizeof(path));

    if (status != 0) {
        printf("FAIL: Self audit returned error (status = %d)\n", status);
    } else {
        printf("PASS: Self binary intact -> %s\n", path);
    }
}

static void test_deleted_process(void)
{
    pid_t child;
    char path[PATH_MAX];
    int status;

    printf("Testing unlinked execution detection...\n");

    if (system("cp test_exe /tmp/proc_sentry_dummy") != 0) {
        printf("FAIL: Could not set up dummy binary in /tmp\n");
        return;
    }

    child = fork();
    if (child == 0) {
        execl("/tmp/proc_sentry_dummy", "proc_sentry_dummy", "--child", (char *)NULL);
        exit(EXIT_FAILURE);
    }

    /* Allow child to start, then unlink binary from disk */
    sleep(1);
    unlink("/tmp/proc_sentry_dummy");

    status = audit_process_exe(child, path, sizeof(path));

    if (status == 1) {
        printf("PASS: Correctly caught unlinked binary -> %s\n", path);
    } else {
        printf("FAIL: Expected status 1, got %d (path: %s)\n", status, path);
    }

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
}

int main(int argc, char *argv[])
{
    if (argc > 1 && strcmp(argv[1], "--child") == 0) {
        pause();
        return EXIT_SUCCESS;
    }

    test_normal_process();
    test_deleted_process();
    return EXIT_SUCCESS;
}
