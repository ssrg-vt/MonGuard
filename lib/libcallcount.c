#define _GNU_SOURCE
#include <stdio.h>

/* Library function used to test number of lib call counts monguard */
void start_libcall_count()
{
	fprintf(stderr, "%s not overidden", __func__);
}

void end_libcall_count()
{
	fprintf(stderr, "%s not overidden", __func__);
}
