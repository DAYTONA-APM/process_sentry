#ifndef MAPS_AUDIT_H
#define MAPS_AUDIT_H

#include <sys/types.h>
#include <stddef.h>

#define ANOMALY_NONE        0
#define ANOMALY_RWX         (1 << 0)  /* W^X violation found anywhere= 0001*/
#define ANOMALY_ANON_EXEC   (1 << 1)  /* Random exe found anywhere = 0010 */

/* 2 indicators of memory tampering & code injection:
 * 1.
 * 		- W & X violations: any rergion that is writable and executable
 * 		- in modern OSs, most processes are either W or X, rarely both
 * 		- anything here is LIKELY to be random shellcode, malicious
 *
 * 2.
 * 		- Anonymous executable memory: aa process that can execute
 * 		but the pathname field is absent.
 * 		- legitimate codes should map from system binaries on the
 * 		file system on the computter (/lib/- or /usr/bin).
 * 		Unbacked exe pages point to runtime allocation nmap, typical
 * 		of injected payloads
 */

typedef struct {
    unsigned long start_addr;
    unsigned long end_addr;
    char perms[5];      /* e.g., "rwxp" + '\0' */
    int anomaly_flags;  /* Bitmask of ANOMALY_* */
    char pathname[256]; /* Backing file or empty if anonymous */
} map_region_t;


/* Pipeline steps:
 *
 * 1. Access and construct the path:
 * 		- build the virtual path
 * 		- try open the file 
 * 		- if it faiils, the process doesn't exist or is done
 *
 * 2. Read the stream line by line:
 * 		- parse the files in a line
 * 		- validate if the core fields line up
 *
 * 3. Evaluate for anomalies:
 * 		- evaluate the permissions of the file for read/write violations
 * 		- if the region is executable, check if the pathname is empty,
 * 		  or if the fscanf didn't match all the fields present
 * 		  - if so, flag that as an ANON_EXEC error
 *
 * 		- sometimes, both fields can be triggered
 */



/*
 * parses the /proc/pid/maps
 * fills the findings array with up to 'max_finding anomalous regions
 *
 * pid_t *pid -> target prrocess to inispect
 *
 * returns:	
 *		>= 0: bitmask for all the observed errors in the process lifecycle
 *		  -1: error opening/reading maps file
 */

int audit_process_maps(pid_t pid);

#endif
