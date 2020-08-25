# MonGuard
Artifact of the MonGuard paper (EuroSec'20):
[Secure and Efficient In-process Monitor (and Library) Protection with Intel MPK](https://www.ssrg.ece.vt.edu/papers/eurosec20.pdf)

Monguard is a system in which a high-performance in-process monitor is efficiently isolated from the rest of the application. To that aim, we leverage the Intel Memory Protection Key(MPK) technology to enforce execute-only memory, combined with code randomization to protect and hide a in-process monitor library. This repository holds a prototype of MonGuard as a loader extension.

Currently the protected monitor does not perform anything other than setting up the protection itself as we are only benchmarking the performance of the monitor protection and not the performance of the monitor itself. However, it provides the opportunity to add in LD_PRELOADs to monitor the libc calls if required. See `src/monitor_overrides.c` for an example of where to put the preloads. These are currently commented out.

Further, this work has been augmented with a single assembly trampoline across all libc calls to facilitate the switching of MPK by writing to the PKRU register. This trampoline also functions to enable a per-thread safe-stack which is switched in/out when jumping in/out of the protected memory region.


## Installation Guide

First and foremost it is important to note that this is a PoC implementation. We make no guarantees about the installation working across different systems. This was tested with a Debian 4.9 machine operating on the x86_64 architecture. Your system should have a processor with the Intel MPK security feature.

1) Navigate to the included musl-libc directory and run `make && sudo make install`
2) Go back out to the root directory of monguard then run `make && sudo make install`
3) You're done, monguard should be installed now. We've included some example targets such as redis and nginx. In order to run them, you'll need to build both of them with the installed musl.

## Running Nginx
* Go into the nginx directory and run `./myconfig.sh`. This should perform the configure step with the required flags and musl. Return to the main MonGuard directory and run nginx by executing `make nginx_run` or `make nginx_debug` for the debug version (requires gdb).

## Running Redis
* No configure step required. However, we have not tested Redis with ASLR enabled, so you will have to disable ASLR (`echo 0 > /proc/sys/kernel/randomize_va_space`).
* Next, just run redis using the provided target `make redis_run` or `make redis_debug` (also requires gdb).
