#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "crawler.h"

#define MAX_TEST_PIDS 2048

static void test_is_numeric_dir(void)
{
    printf("[*] Testing is_numeric_dir()...\n");
    if (!is_numeric_dir("1234"))  printf("[-] FAIL: Valid digits rejected\n");
    if (is_numeric_dir("12a4"))   printf("[-] FAIL: Mixed alphanumeric accepted\n");
    if (is_numeric_dir("-123"))   printf("[-] FAIL: Negative sign accepted\n");
    if (is_numeric_dir(""))       printf("[-] FAIL: Empty string accepted\n");
    if (is_numeric_dir(NULL))     printf("[-] FAIL: NULL pointer accepted\n");
    printf("[+] is_numeric_dir() checks complete.\n");
}

static void test_crawler_execution(void)
{
    pid_t pids[MAX_TEST_PIDS];
    pid_t my_pid;
    int total;
    int found_self;
    int i;

    printf("[*] Testing crawl_proc_pids()...\n");
    my_pid = getpid();
    total = crawl_proc_pids(pids, MAX_TEST_PIDS);

    if (total <= 0) {
        printf("[-] FAIL: No processes crawled (total = %d)\n", total);
        return;
    }

    found_self = 0;
    for (i = 0; i < total; i++) {
        if (pids[i] == my_pid) {
            found_self = 1;
            break;
        }
    }

    if (!found_self) {
        printf("FAIL: Current process PID (%ld) not found in /proc crawl\n", (long)my_pid);
    } else {
        printf("PASS: Successfully crawled %d PIDs and verified self (PID %ld)\n", total, (long)my_pid);
    }
}

int main(void)
{
    test_is_numeric_dir();
    test_crawler_execution();
    return EXIT_SUCCESS;
}
