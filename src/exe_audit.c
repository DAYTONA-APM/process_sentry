#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>

#include "exe_audit.h"

/*
 * so, /proc/pid/exe is a symbolic link to point directly to the on-disk
 * executable file backing a process.
 *
 * when a binary is unlinked/deleted from disk, the kernel never crashes
 * the program.
 * the open inode is active in memory, but the kernel add " (deleted)" to
 * the target path reported by /prod/pid/exe.
 *
 * this is an indicator of evasion
 * 		- an operator executes a payload and immediately unlinks the file
 * 		to complicate the finding process
 *
 * fopen would follow the symlink and open the file, but we only need the 
 * dest path string, so we'll be using "readlink()" s/o to POSIX (unistd.h)
 *
 * ssize_t readlink(const char *src, char *buf, size_t bufsize);
 *
 * but there is a catch, no null terminator
 * so strings must be terminated before printing
 */

int audit_process_exe(pid_t pid, char *exe_buf, size_t buf_size)
{
	char process_path[100];
	ssize_t len;
	const char *deleted_tag;

	if (!exe_buf || buf_size <= 0) {
		fprintf(stderr, "invalid inputs were provided\n");
		return -1;
	}

	/* we format the target string */
	sprintf(process_path, "/proc/%d/exe", pid);

	/* read the link destination, with a spare byte for  '\0' */
	len = readlink(process_path, exe_buf, buf_size - 1);
	if (len == -1) {
		/* this fails, ssize_t returns -1 if all else fails */
		return -1;
	}

	/* manually  null_terminate */
	exe_buf[len] = '\0';

	/* checking for unliinked execution tag */
	/* strstr:
	 * char *strstr(const char haystack, const char needle)
	 * 		if substring isn't found, it returns NULL
	 * 		if the needle is an empty string, the haystack is returned
	 * 		from string.h
	 */
	deleted_tag = " (deleted)";
	if (strstr(exe_buf, deleted_tag) != NULL) {
		return 1; /* the binary was deleted from the disk */
	}

	/* otherwise, all is normal */
	return 0;
}
