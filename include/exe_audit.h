#ifndef EXE_AUDIT_H
#define EXE_AUDIT_H

#include <sys/types.h>

/*
 * inspects /proc/(pid)/exe for a given PID
 * - exe_buf:  buffer to resolve the unresolved path
 * - buf_size: total allocated capacity of exe_buf
 *
 *   pid = process to inspect
 *   exe_buf = output buffer for the executaable path
 *   buf_sie = the total capaacity of exe_buf
 *
 * Returns:
 * 		1 -> the binary is running but marked (deleted) on disk
 * 		0 if the binary exists normally on disk
 * 		-1 if the link couldn't be read. (permssions or PID exited)
 */

int audit_process_exe(pid_t pid, char *exe_buf, size_t buf_size);

#endif
