#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/types.h>

#include "crawler.h"


int is_numeric_dir(const char *name)
{
	int PIDs;
	const char *p; /* the current character under evaluation */

	if (!name || name = "\0") {
		fprintf(stderr, "no name provided\n");
		return -1; /* the mem_err option */
	}

	p = name;
	while (*p != '\0') {
		if (!isdigit(*p)) {
			return 0; /* invalid */
		}
		p++;
	}
	
	return 1;  /* valid */
}

/* upon evaluation, PID_T as a type holds the same properties as a
 * standard integer. the only difference is a change of the label for 
 * readability purposes.
 *
 * it is within the <sys/types.h> liibrary 
 */ 
int crawl_proc_pids(pid_t *pid_list, int max_pids)
{
	DIR *dir; /* a cursor keeping track of my curr pos */
	struct dirent *entry;
	/* 
	 * dirent is a struct defined as such:
	 *
	 * ino_t = d_ino --> inode number
	 * off_t = d_off --> offset to the next dirent
	 * uns_short = d_reclen -> length of the current record
	 * uns_char  = d_type   -> the type of file (dir, file etc.)
	 * char		 = d_name   -> the null terminated filename
	 *
	 * the only field that WE need is d_name
	 * 	- it is just a collection of strings
	 * 	- it doesn't include the parent path
	 * 	- proc/456 --> d_name = "456"
	 */
	int count;

	if (!pid_list || max_pids <= 0) {
		fprintf(stderr, "invalid inputs provided\n");
		return 0;
	}

	/* open the directory here */
	dir = opendir("/proc"); /* open at this target address */
	if (dir == NULL) {
		perror("opendir(/proc)");
		return -1;
	}
	/* readdir is meant to grab the curr item and advance to the next */

	count = 0;

	/* read the entries until the stream runs dry */
	while((entry = readdir(dir)) != NULL) {
		if (is_numeric_dir(entry->d_name)) {
			/* prevention of buffer overflow */
			if (count >= max_pids) {
				break;
			}
			pid_list[count] = (pid_t)atoi(entry->d_name);
		}
	}


	closedir(dir); /* tell the loop, nothing is left, similar to fclose */
	return count;
}
