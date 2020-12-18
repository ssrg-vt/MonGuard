#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <stddef.h>
#include <semaphore.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>

/* Local headers */
#include <debug.h>
#include <config.h>
#include <libmonitor.h>
#include <pkey.h>
#include <loader.h>

uint64_t track_libc_count = 0;
uint64_t num_libc_calls = 0;

void __attribute__ ((constructor)) init_tramp(int argc, char** argv, char** env)
{
	/*Call this guy all the time first */
	store_original_functions();
	init_loader();
	log_info("Trampoline library instantiated");
	associate_all_pkeys();
}

void associate_all_pkeys()
{
	unsigned long pkey;
	proc_info_t monitor_info, libc_info;
	DEACTIVATE();
	/* Allocate pkey */
	pkey = syscall(SYS_pkey_alloc, 0, 0);

	log_debug("Pkey allocated is: %lu", pkey);

	/* Associate keys with both the monitor and libc */
	read_proc("libmonitor", &monitor_info);
	read_proc("libc", &libc_info);
	/* Associate pages of the libraries with the allocated pkey */
	associate_pkey_library(&libc_info, pkey);
	associate_pkey_library(&monitor_info, pkey);
	DEACTIVATE();
}

void start_libcall_count()
{
	track_libc_count |= 0x1;
}

void end_libcall_count()
{
	track_libc_count &= 0x0;
	//log_debug("Libc call count in protected section: %d", num_libc_calls);
}
