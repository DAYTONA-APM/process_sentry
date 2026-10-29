#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

#include "crawler.h"
#include "exe_audit.h"
#include "maps_audit.h"
#include "env_audit.h"

#define	MAX_PROC_IDS 4096
#define PATH_BUF_SIZE 1024
#define DEFAULT_INTERVAL 2

/* building blocks:	
 * 		- crawl_proc_pids = finds all numerical process IDs in /proc
 * 		- audit_process_exe = tells us if the binary was deleted
 * 		- audit_process_maps = tells us if we see RWX or anonymous exe code
 */

/* now we build the checking loop */

/* 1. give a headerr with the total # of PIDs scanned
 * 2. for each process (sus) found, print an alert entry showing:
 * 		- PID
 * 		- Binary Path
 * 		- Memory Anomalies
 *
 * 3. a summary at the bottom
 * 		- totaal processes audited
 * 		- totaal flagged
 * 		- total errors
 *
 *  start crawling through /proc
 *  		-> crawl_proc_pids (build aarray of processes]
 *  		|
 *  		|
 *  		<- for each PID  ->
 *
 *  				-> audit_process_exe()
 *  				-> audit process_maps()
 *
 *  		->  evaluate flags:
 *  				- if clean -> pick based on the log
 *  				- if flagged: give the formatted threat alert
 *
 * print the summary fields
 */

static int keep_running = 1;

static void on_sigint(int sig)
{
	(void)sig;
	keep_running = 0;
}


/* performs a full sweep and prints the table */
static int run_audit(void)
{	
	pid_t pids[MAX_PROC_IDS];
	int total_proc_ids;
	int i;
	int flagged_count;
	int ok_count;
	int skip_count;

	pid_t pid;
	char exe_buf[PATH_BUF_SIZE];
	int exe_status;
	int maps_mask;
	int env_mask;
	int is_suspicious;
	const char *disk_str;
	char mem_str[32];
	char env_str[32];
	
	printf("Memory Integrity & Linux Process Auditor\n");

	total_proc_ids = crawl_proc_pids(pids, MAX_PROC_IDS);
	if (total_proc_ids < 0) {
		fprintf(stderr, "cannot read /proc dir \n");
		return 1;
	}

	flagged_count = 0;
	ok_count = 0;
	skip_count = 0;

	printf("proc-sentry: Linux Process & Memory Integrity Table\n");
	printf("%-7s  %-12s  %-10s  %-12s  %-12s  %s\n", "PID", "STATUS", "DISK LINK", "MEMORY", "ENV INJECT", "EXE PATH");

	for (i = 0; i < total_proc_ids; i++) {
		pid = pids[i];
		is_suspicious = 0;
		disk_str = "ok";
		mem_str[0] = '\0';
		exe_buf[0] = '\0';
		env_str[0] = '\0';

		/* 1. stage 1: file link inspection */
		exe_status = audit_process_exe(pid, exe_buf, sizeof(exe_buf));

		/* 2. virtual memory layout inspection */
		maps_mask = audit_process_maps(pid);

		/* env variable injection vectors */
		env_mask = audit_process_env(pid);

		/* kernel threads & fast-exiting processes may not flag */
		if (exe_status < 0 && maps_mask < 0 && env_mask < 0) {
			skip_count++;
			printf("%-7ld  %-12s  %-10s  %-12s  %-12s  %s\n",
                   (long)pid, "[SKIP]", "N/A", "N/A", "N/A", "<kernel/exited>");
			continue;
		}

		/* evaluate the disk_link status */
		if (exe_status == 1) {
			disk_str = "deleted";
			is_suspicious = 1;
		} else if (exe_status == 0) {
			disk_str =  "ok";
		} else {
			disk_str = "err";
		}

		/* evaluate the memory flags */
		/* Evaluate Stage 3 Memory Flags */
        if (maps_mask > 0) {
            if ((maps_mask & ANOMALY_RWX) 
					&& (maps_mask & ANOMALY_ANON_EXEC)) {
                strcpy(mem_str, "RWX|ANON");
                is_suspicious = 1;
            } else if (maps_mask & ANOMALY_RWX) {
                strcpy(mem_str, "RWX");
                is_suspicious = 1;
            } else if (maps_mask & ANOMALY_ANON_EXEC) {
                strcpy(mem_str, "ANON_EXEC");
                is_suspicious = 1;
            } else {
                strcpy(mem_str, "OK");
            }
        } else if (maps_mask == 0) {
            strcpy(mem_str, "OK");
        } else {
            strcpy(mem_str, "ERR");
        }

		/* Evaluate Environment Integrity */
        if (env_mask > 0) {
            is_suspicious = 1;
            if (env_mask & ENV_ANOMALY_PRELOAD) {
                strcpy(env_str, "LD_PRELOAD");
            } else if (env_mask & ENV_ANOMALY_LIBPATH) {
                strcpy(env_str, "LD_LIB_PATH");
            } else if (env_mask & ENV_ANOMALY_AUDIT) {
                strcpy(env_str, "LD_AUDIT");
            } else {
                strcpy(env_str, "ANOMALY");
            }
        } else if (env_mask == 0) {
            strcpy(env_str, "OK");
        } else {
            strcpy(env_str, "ERR");
        }

		/* Emit Row */
        if (is_suspicious) {
            flagged_count++;
            printf("%-7ld  %-12s  %-10s  %-12s  %-12s  %s\n",
                   (long)pid, "[SUSPICIOUS]", disk_str, mem_str, env_str,
                   exe_buf[0] != '\0' ? exe_buf : "<unresolved>");
        } else {
            ok_count++;
            printf("%-7ld  %-12s  %-10s  %-12s  %-12s  %s\n",
                   (long)pid, "[OK]", disk_str, mem_str, env_str,
                   exe_buf[0] != '\0' ? exe_buf : "<unresolved>");
        }
	}

	printf("[+] Summary: %d total | %d OK | %d SUSPICIOUS | %d skipped\n",
           total_proc_ids, ok_count, flagged_count, skip_count);
	
	if (flagged_count < 0) {
		flagged_count = 0;
	}


	return flagged_count;
}

int main(int argc, char **argv)
{
    int interval = 0;

    /*
     * Direct argument check:
     * If argv[1] is "-w", read interval (e.g., ./proc-sentry -w 2)
     */
    if (argc >= 2 && strcmp(argv[1], "-w") == 0) {
        interval = (argc >= 3) ? atoi(argv[2]) : 2;
        if (interval <= 0) {
            interval = 2;
        }
    }

    /* Normal mode: no "-w" flag, just run once and exit */
    if (interval == 0) {
        int flagged = run_audit();
        return (flagged > 0) ? 2 : 0;
    }

    /* Watch mode: register basic Ctrl+C handler and loop */
    signal(SIGINT, on_sigint);

    while (keep_running) {
        /* Clear screen */
        printf("\033[H\033[2J");
		fflush(stdout);

        run_audit();
        printf("Refreshing every %d sec. Press Ctrl+C to quit.\n", interval);
		fflush(stdout);

        sleep(interval);
    }

    printf("\nExited cleanly.\n");
    return 0;
}
