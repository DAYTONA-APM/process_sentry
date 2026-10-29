#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include "env_audit.h"

#define ENV_BUF_SIZE 4096


int audit_process_env(pid_t pid)
{
    char env_path[64];
    char buf[ENV_BUF_SIZE];
    int fd;
    ssize_t bytes_read;
    int anomaly_mask;
    size_t i;
    size_t var_start;

    sprintf(env_path, "/proc/%ld/environ", (long)pid);

    fd = open(env_path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    anomaly_mask = ENV_ANOMALY_NONE;

	/*
     * /proc/[pid]/environ consists of strings formatted as "KEY=VALUE\0".
     * Read the stream into our buffer and scan each null-delimited token.
     */
    while ((bytes_read = read(fd, buf, sizeof(buf))) > 0) {
        var_start = 0;

        for (i = 0; i < (size_t)bytes_read; i++) {
            if (buf[i] == '\0') {
                const char *var = &buf[var_start];

                if (strncmp(var, "LD_PRELOAD=", 11) == 0) {
                    anomaly_mask |= ENV_ANOMALY_PRELOAD;
                } else if (strncmp(var, "LD_LIBRARY_PATH=", 16) == 0) {
                    anomaly_mask |= ENV_ANOMALY_LIBPATH;
                } else if (strncmp(var, "LD_AUDIT=", 9) == 0) {
                    anomaly_mask |= ENV_ANOMALY_AUDIT;
                }

                var_start = i + 1;
            }
        }
    }

    close(fd);
    return anomaly_mask;
}
