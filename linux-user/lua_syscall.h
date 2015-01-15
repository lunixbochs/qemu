#include <lua.h>
#include "cpu.h"

extern abi_long lua_hook_syscall(
    void *cpu_env, int num, abi_long arg1,
    abi_long arg2, abi_long arg3, abi_long arg4,
    abi_long arg5, abi_long arg6, abi_long arg7,
    abi_long arg8);
