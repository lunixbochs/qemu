#ifndef LUA_UTIL_H
#define LUA_UTIL_H

#include <sys/mman.h>
#include "qemu.h"

#define target_malloc(size) g2h(target_mmap(0, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0))
#define target_free(addr, size) target_munmap(h2g(addr), size)

#endif
