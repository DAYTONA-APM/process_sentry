#ifndef ENV_AUDIT_H
#define ENV_AUDIT_H

#include <sys/types.h>

/**
 * we mean to find dynamic linker hijacking variables:
 * 		LD_PRELOAD: injects an arbitrary .so into the process addr space
 * 				- forces the linkerr (ld.so) to load an attacker's lib
 * 				  before any other libirary
 * 				- malicious actors use this for rootkits to hijack C lib
 * 				  calls like readdir, to hide files or sniff network pkts
 *
 * 		LD_LIBRARY_PATH: overrides system lib resolution paths
 *				- alters the search order for shared objects
 *				- can spoof fake library locations
 * 				- (DLL/SO spoofing)
 *
 * 		LD_AUDIT: instructs the linker to invoke tracing callbacks from
 * 				  an arbitrary library
 * 				- this an auditing endpoint that notifes a lib about link
 * 			      events
 * 			    - often exploited to run unauthorized code in privileged
 * 			      processes.
 */

#define ENV_ANOMALY_NONE        0
#define ENV_ANOMALY_PRELOAD    (1 << 0)  /* LD_PRELOAD present */
#define ENV_ANOMALY_LIBPATH    (1 << 1)  /* LD_LIBRARY_PATH present */
#define ENV_ANOMALY_AUDIT      (1 << 2)  /* LD_AUDIT present */

/**
 * inspecting /proc/[pid]/environ for dynamic linker overrides 
 *
 * scans the null-delimited environment var array of a process
 * for inidicators of shared libraries
 *
 * pid -> Process to inspect
 * @return the bitmask of the ENV_ANOMALY if found
 */
int audit_process_env(pid_t pid);

#endif
