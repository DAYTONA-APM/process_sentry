#ifndef CRAWLER_H
#define CRAWLER_H

#include <sys/types.h>

/* 
 * intends to valid if a dir name has only ASCII digits
 * return 1 if valid, 0 otherwise
 */
int is_numeric_dir(const char *name);

/*
 * move through /proc and fill the PID list with active process IDs
 * - pid_list = pre-allocated array of pid_t
 * - max_pids = maximum elements that pid_list can store
 *
 * returrs the number of PIDs collected, or -1 on directory open erro
 */
int crawl_proc_pids(pid_t *pid_list, int max_pids);

#endif
