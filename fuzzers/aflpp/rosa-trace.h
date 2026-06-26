#ifndef __ROSA_TRACE_H__
#define __ROSA_TRACE_H__


#include <unistd.h>
#include <errno.h>


// Define the ROSA trace marker.
//
// When ROSA collects traces (specifically, the system call part) through `strace`, it needs a
// marker to know where the "starting point" of the trace is, in order to avoid system calls which
// should not be part of the trace (e.g., the `execve()` call to the target program itself).
//
// The target program can simply call this macro to insert the marker where needed.
#define __ROSA_TRACE_START() \
    do { \
        write(-1, "__ROSAS_CANTINA__", 17); \
        errno = 0; \
    } while(0)


#endif  // __ROSA_TRACE_H__
