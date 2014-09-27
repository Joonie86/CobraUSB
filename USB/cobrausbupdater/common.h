#ifndef __COMMON_H__
#define __COMMON_H__

#ifdef DEBUG
#define DPRINTF printf
#else
#define DPRINTF(...)
#endif

#undef MAX_PATH
#define MAX_PATH	0x420

#endif /* COMMON_H */

