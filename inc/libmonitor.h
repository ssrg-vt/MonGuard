#ifndef __LIBMONITOR_H__
#define __LIBMONITOR_H__
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>

void store_child_pid(unsigned long pid);
void associate_all_pkeys();

#endif
