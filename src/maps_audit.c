#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "maps_audit.h"

/* example string for proc/[pid]/maps:
 * 		7f8a9c000000-7f8a9c010000 rwxp 00000000 00:00 0 /usr/lib/libc.so
 */

int audit_process_maps(pid_t pid)
{
	char maps_path[64];
	char line[512];
	FILE *fp;
	int anomaly_mask;

	unsigned long start_path;
	unsigned long end_path;
	char permissions[5];
	unsigned long offset;
	unsigned int dev_major;
	unsigned int dev_minor;
	unsigned long inode;
	char pathname[256];
	int fields;

	sprintf(maps_path, "/proc/%ld/maps", (long)pid);
	fp = fopen(maps_path, "r");
	if (!fp)
		return -1;

	anomaly_mask = ANOMALY_NONE; /* 0000 */
	
	while(fgets(line, sizeof(line), fp) != NULL) {
		pathname[0] = '\0'; /* reset from prev iterations */

		fields = sscanf(line, "%lx-%lx %4s %lx %x:%x %lu %255[^\n]",
						&start_path, &end_path, permissions, &offset,
						&dev_major, &dev_minor, &inode, pathname);

		if (fields < 7) {
			continue;  /* incomplete data */
		}

		/* check 1: write & execute violations */
		if (permissions[1] == 'w' && permissions[2] == 'x') 
			anomaly_mask |= ANOMALY_RWX; /* activation */

		/* check 2: anonymous execution */
		if (permissions[2] == 'x') {
			if (fields == 7 || pathname[0] == '\0') {
				anomaly_mask |= ANOMALY_ANON_EXEC;
			}
		}
	}
	fclose(fp);

	return anomaly_mask;
}
