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
#ifdef TARGET_NR_exit
    _(exit,      NUM_T),
#endif
#ifdef TARGET_NR_fork
    _(fork,      PTR_T),
#endif
#ifdef TARGET_NR_read
    _(read,      NUM_T, PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_write
    _(write,     NUM_T, STR_T, NUM_T),
#endif
#ifdef TARGET_NR_open
    _(open,      STR_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_close
    _(close,     NUM_T),
#endif
#ifdef TARGET_NR_waitpid
    _(waitpid,   NUM_T, PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_creat
    _(creat,     STR_T, NUM_T),
#endif
#ifdef TARGET_NR_link
    _(link,      STR_T, STR_T),
#endif
#ifdef TARGET_NR_unlink
    _(unlink,    STR_T),
#endif
#ifdef TARGET_NR_execve
    _(execve,    PTR_T),
#endif
#ifdef TARGET_NR_chdir
    _(chdir,     STR_T),
#endif
#ifdef TARGET_NR_time
    _(time,      PTR_T),
#endif
#ifdef TARGET_NR_mknod
    _(mknod,     STR_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_chmod
    _(chmod,     STR_T, NUM_T),
#endif
#ifdef TARGET_NR_lchown
    _(lchown,    STR_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_break
    [TARGET_NR_break] = {TARGET_NR_break, "break"},
#endif
#ifdef TARGET_NR_stat
    _(stat,      STR_T, PTR_T),
#endif
#ifdef TARGET_NR_lseek
    _(lseek,     NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_getpid
    _(getpid),
#endif
#ifdef TARGET_NR_mount
    _(mount,     STR_T, STR_T, STR_T, NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_setuid
    _(setuid,    NUM_T),
#endif
#ifdef TARGET_NR_getuid
    _(getuid),
#endif
#ifdef TARGET_NR_stime
    _(stime,     PTR_T),
#endif
#ifdef TARGET_NR_ptrace
    _(ptrace,    NUM_T, NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_alarm
    _(alarm,     NUM_T),
#endif
#ifdef TARGET_NR_fstat
    _(fstat,     NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_pause
    _(pause),
#endif
#ifdef TARGET_NR_utime
    _(utime,     STR_T, PTR_T),
#endif
#ifdef TARGET_NR_access
    _(access,    STR_T, NUM_T),
#endif
#ifdef TARGET_NR_nice
    _(nice,      NUM_T),
#endif
#ifdef TARGET_NR_sync
    _(sync),
#endif
#ifdef TARGET_NR_kill
    _(kill,      NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_rename
    _(rename,    STR_T, STR_T),
#endif
#ifdef TARGET_NR_mkdir
    _(mkdir,     STR_T, NUM_T),
#endif
#ifdef TARGET_NR_rmdir
    _(rmdir,     STR_T),
#endif
#ifdef TARGET_NR_dup
    _(dup,       NUM_T),
#endif
#ifdef TARGET_NR_pipe
    _(pipe,      PTR_T),
#endif
#ifdef TARGET_NR_times
    _(times,     PTR_T),
#endif
#ifdef TARGET_NR_brk
    _(brk,       NUM_T),
#endif
#ifdef TARGET_NR_setgid
    _(setgid,    NUM_T),
#endif
#ifdef TARGET_NR_getgid
    _(getgid),
#endif
#ifdef TARGET_NR_signal
    _(signal,    NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_geteuid
    _(geteuid),
#endif
#ifdef TARGET_NR_getegid
    _(getegid),
#endif
#ifdef TARGET_NR_acct
    _(acct,      STR_T),
#endif
#ifdef TARGET_NR_umount
    _(umount,    STR_T, NUM_T),
#endif
#ifdef TARGET_NR_ioctl
    _(ioctl,     NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_fcntl
    _(fcntl,     NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_setpgid
    _(setpgid,   NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_olduname
    _(olduname,  PTR_T),
#endif
#ifdef TARGET_NR_umask
    _(umask,     NUM_T),
#endif
#ifdef TARGET_NR_chroot
    _(chroot,    STR_T),
#endif
#ifdef TARGET_NR_ustat
    _(ustat,     NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_dup2
    _(dup2,                   NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_getppid
    _(getppid),
#endif
#ifdef TARGET_NR_getpgrp
    _(getpgrp),
#endif
#ifdef TARGET_NR_setsid
    _(setsid),
#endif
#ifdef TARGET_NR_sigaction
    _(sigaction,              NUM_T, PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_sgetmask
    _(sgetmask),
#endif
#ifdef TARGET_NR_ssetmask
    _(ssetmask,               NUM_T),
#endif
#ifdef TARGET_NR_setreuid
    _(setreuid,               NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_setregid
    _(setregid,               NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_sigsuspend
    _(sigsuspend,             NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_sigpending
    _(sigpending,             PTR_T),
#endif
#ifdef TARGET_NR_sethostname
    _(sethostname,            STR_T, NUM_T),
#endif
#ifdef TARGET_NR_setrlimit
    _(setrlimit,              NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_getrlimit
    _(getrlimit,              NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_getrusage
    _(getrusage,              NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_gettimeofday
    _(gettimeofday,           PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_settimeofday
    _(settimeofday,           PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_getgroups
    _(getgroups,              NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_setgroups
    _(setgroups,              NUM_T, PTR_T),
#endif
    // old_select,               PTR_T),
#ifdef TARGET_NR_symlink
    _(symlink,                STR_T, STR_T),
#endif
#ifdef TARGET_NR_lstat
    _(lstat,                  STR_T, PTR_T),
#endif
#ifdef TARGET_NR_readlink
    _(readlink,               STR_T, STR_T, NUM_T),
#endif
#ifdef TARGET_NR_uselib
    _(uselib,                 STR_T),
#endif
#ifdef TARGET_NR_swapon
    _(swapon,                 STR_T, NUM_T),
#endif
#ifdef TARGET_NR_reboot
    _(reboot,                 NUM_T, NUM_T, NUM_T, PTR_T),
#endif
    // old_readdir,              NUM_T, PTR_T, NUM_T),
    // old_mmap,                 PTR_T),
#ifdef TARGET_NR_munmap
    _(munmap,                 NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_truncate
    _(truncate,               STR_T, NUM_T),
#endif
#ifdef TARGET_NR_ftruncate
    _(ftruncate,              NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_fchmod
    _(fchmod,                 NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_fchown
    _(fchown,                 NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_getpriority
    _(getpriority,            NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_setpriority
    _(setpriority,            NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_statfs
    _(statfs,                 STR_T, PTR_T),
#endif
#ifdef TARGET_NR_fstatfs
    _(fstatfs,                NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_ioperm
    _(ioperm,                 NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_socketcall
    _(socketcall,             NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_syslog
    _(syslog,                 NUM_T, STR_T, NUM_T),
#endif
#ifdef TARGET_NR_setitimer
    _(setitimer,              NUM_T, PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_getitimer
    _(getitimer,              NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_newstat
    _(newstat,                STR_T, PTR_T),
#endif
#ifdef TARGET_NR_newlstat
    _(newlstat,               STR_T, PTR_T),
#endif
#ifdef TARGET_NR_newfstat
    _(newfstat,               NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_uname
    _(uname,                  PTR_T),
#endif
#ifdef TARGET_NR_iopl
    _(iopl,                   NUM_T),
#endif
#ifdef TARGET_NR_vhangup
    _(vhangup),
#endif
#ifdef TARGET_NR_idle
    _(idle),
#endif
#ifdef TARGET_NR_vm86old
    _(vm86old,                NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_wait4
    _(wait4,                  NUM_T, PTR_T, NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_swapoff
    _(swapoff,                STR_T),
#endif
#ifdef TARGET_NR_sysinfo
    _(sysinfo,                PTR_T),
#endif
#ifdef TARGET_NR_ipc
    _(ipc,                    NUM_T, NUM_T, NUM_T, NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_fsync
    _(fsync,                  NUM_T),
#endif
#ifdef TARGET_NR_sigreturn
    _(sigreturn,              NUM_T),
#endif
#ifdef TARGET_NR_clone
    _(clone,                  PTR_T),
#endif
#ifdef TARGET_NR_setdomainname
    _(setdomainname,          STR_T, NUM_T),
#endif
#ifdef TARGET_NR_newuname
    _(newuname,               PTR_T),
#endif
#ifdef TARGET_NR_modify_ldt
    _(modify_ldt,             NUM_T, PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_adjtimex
    _(adjtimex,               PTR_T),
#endif
#ifdef TARGET_NR_mprotect
    _(mprotect,               NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_sigprocmask
    _(sigprocmask,            NUM_T, PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_create_module
    _(create_module,          STR_T, NUM_T),
#endif
#ifdef TARGET_NR_init_module
    _(init_module,            STR_T, PTR_T),
#endif
#ifdef TARGET_NR_delete_module
    _(delete_module,          STR_T),
#endif
#ifdef TARGET_NR_get_kernel_syms
    _(get_kernel_syms,        PTR_T),
#endif
#ifdef TARGET_NR_quotactl
    _(quotactl,               NUM_T, STR_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_getpgid
    _(getpgid,                NUM_T),
#endif
#ifdef TARGET_NR_fchdir
    _(fchdir,                 NUM_T),
#endif
#ifdef TARGET_NR_bdflush
    _(bdflush,                NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_sysfs
    _(sysfs,                  NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_personality
    _(personality,            NUM_T),
#endif
#ifdef TARGET_NR_setfsuid
    _(setfsuid,               NUM_T),
#endif
#ifdef TARGET_NR_setfsgid
    _(setfsgid,               NUM_T),
#endif
#ifdef TARGET_NR_llseek
    _(llseek,                 NUM_T, NUM_T, NUM_T, PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_getdents
    _(getdents,               NUM_T, PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_select
    _(select,                 NUM_T, PTR_T, PTR_T, PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_flock
    _(flock,                  NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_msync
    _(msync,                  NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_readv
    _(readv,                  NUM_T, PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_writev
    _(writev,                 NUM_T, PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_getsid
    _(getsid,                 NUM_T),
#endif
#ifdef TARGET_NR_fdatasync
    _(fdatasync,              NUM_T),
#endif
#ifdef TARGET_NR_sysctl
    _(sysctl,                 PTR_T),
#endif
#ifdef TARGET_NR_mlock
    _(mlock,                  NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_munlock
    _(munlock,                NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_mlockall
    _(mlockall,               NUM_T),
#endif
#ifdef TARGET_NR_munlockall
    _(munlockall),
#endif
#ifdef TARGET_NR_sched_setparam
    _(sched_setparam,         NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_sched_getparam
    _(sched_getparam,         NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_sched_setscheduler
    _(sched_setscheduler,     NUM_T, NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_sched_getscheduler
    _(sched_getscheduler,     NUM_T),
#endif
#ifdef TARGET_NR_sched_yield
    _(sched_yield),
#endif
#ifdef TARGET_NR_sched_get_priority_max
    _(sched_get_priority_max, NUM_T),
#endif
#ifdef TARGET_NR_sched_get_priority_min
    _(sched_get_priority_min, NUM_T),
#endif
#ifdef TARGET_NR_sched_rr_get_interval
    _(sched_rr_get_interval,  NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_nanosleep
    _(nanosleep,              PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_mremap
    _(mremap,                 NUM_T, NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_setresuid
    _(setresuid,              NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_getresuid
    _(getresuid,              PTR_T, PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_vm86
    _(vm86,                   PTR_T),
#endif
#ifdef TARGET_NR_query_module
    _(query_module,           STR_T, NUM_T, STR_T, NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_poll
    _(poll,                   PTR_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_nfsservctl
    _(nfsservctl,             NUM_T, PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_setresgid
    _(setresgid,              NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_getresgid
    _(getresgid,              PTR_T, PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_prctl
    _(prctl,                  NUM_T, NUM_T, NUM_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_rt_sigreturn
    _(rt_sigreturn,           NUM_T),
#endif
#ifdef TARGET_NR_rt_sigaction
    _(rt_sigaction,           NUM_T, PTR_T, PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_rt_sigprocmask
    _(rt_sigprocmask,         NUM_T, PTR_T, PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_rt_sigpending
    _(rt_sigpending,          PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_rt_sigtimedwait
    _(rt_sigtimedwait,        PTR_T, PTR_T, PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_rt_sigqueueinfo
    _(rt_sigqueueinfo,        NUM_T, NUM_T, PTR_T),
#endif
#ifdef TARGET_NR_rt_sigsuspend
    _(rt_sigsuspend,          PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_pread
    _(pread,                  NUM_T, STR_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_pwrite
    _(pwrite,                 NUM_T, STR_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_chown
    _(chown,                  STR_T, NUM_T, NUM_T),
#endif
#ifdef TARGET_NR_getcwd
    _(getcwd,                 STR_T, NUM_T),
#endif
#ifdef TARGET_NR_capget
    _(capget,                 PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_capset
    _(capset,                 PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_sigaltstack
    _(sigaltstack,            PTR_T, PTR_T),
#endif
#ifdef TARGET_NR_sendfile
    _(sendfile,               NUM_T, NUM_T, PTR_T, NUM_T),
#endif
#ifdef TARGET_NR_vfork
    _(vfork,                  PTR_T),
#endif
};

#endif
