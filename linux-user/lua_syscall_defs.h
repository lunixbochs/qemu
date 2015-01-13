#ifndef LUA_SYSCALL_DEFS_H
#define LUA_SYSCALL_DEFS_H

#include "qemu.h"
#include "lua.h"

#define NUM_T 1
#define STR_T 2
#define PTR_T 3

typedef struct {
    int num;
    const char *name;
    int args[9];
} lua_syscall_def;

#define _(name, ...) [TARGET_NR_##name] = {TARGET_NR_##name, #name, {__VA_ARGS__}}

static lua_syscall_def lua_syscall_defs[] = {
    _(exit,      NUM_T),
    _(fork),
    _(read,      NUM_T, PTR_T, NUM_T),
    _(write,     NUM_T, STR_T, NUM_T),
    _(open,      STR_T, NUM_T, NUM_T),
    _(close,     NUM_T),
#ifdef TARGET_NR_waitpid
    _(waitpid,   NUM_T, PTR_T, NUM_T),
#endif
    _(creat,     STR_T, NUM_T),
    _(link,      STR_T, STR_T),
    _(unlink,    STR_T),
//    _(execve,    ????),
    _(chdir,     STR_T),
    _(time,      PTR_T),
    _(mknod,     STR_T, NUM_T, NUM_T),
    _(chmod,     STR_T, NUM_T),
    _(lchown,    STR_T, NUM_T, NUM_T),
#ifdef TARGET_NR_break
    [TARGET_NR_break] = {TARGET_NR_break, "break"},
#endif
    _(stat,      STR_T, PTR_T),
    _(lseek,     NUM_T, NUM_T, NUM_T),
    _(getpid),
    _(mount,     STR_T, STR_T, STR_T, NUM_T, PTR_T),
#ifdef TARGET_NR_umount
    _(umount,    STR_T),
#endif
    _(setuid,    NUM_T),
    _(getuid),
#ifdef TARGET_NR_stime
    _(stime,     PTR_T),
#endif
    _(ptrace,    NUM_T, NUM_T, NUM_T, NUM_T),
    _(alarm,     NUM_T),
    _(fstat,     NUM_T, PTR_T),
    _(pause),
    _(utime,     STR_T, PTR_T),
};

#endif
