#include <stdio.h>

#include "lua.h"
#include "qemu.h"

abi_long lua_hook_syscall(
    void *cpu_env, int num, abi_long arg1,
    abi_long arg2, abi_long arg3, abi_long arg4,
    abi_long arg5, abi_long arg6, abi_long arg7,
    abi_long arg8) {
    return do_syscall_nolua(cpu_env, num, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
}


/*
int i;
for (i = 0; i < nsyscalls; i++) {
    if (scnames[i].nr == num) {
        if (scnames[i].call != NULL) {
            scnames[i].call(&scnames[i], arg1, arg2, arg3, arg4, arg5, arg6);
        } else {
            if (scnames[i].format != NULL)
                format = scnames[i].format;
            gemu_log(format, scnames[i].name, arg1, arg2, arg3, arg4, arg5, arg6);
        }
        return;
    }
}
*/

static int lua_err_tostring(lua_State *L) {
    double d = lua_tonumber(L, 1);
    const char *name = "unknown";
    switch ((int)d) {
    #define err(e) case e: name = #e; break;
    #include "lua_err.h"
    #undef err
    }
    lua_pushstring(L, name);
    return 1;
}

void lua_set_globals(lua_State *L) {
    lua_newtable(L);
    #define err(e) \
        lua_pushstring(L, #e); \
        lua_pushnumber(L, e); \
        lua_settable(L, -3);
    #include "lua_err.h"
    #undef err
    // err.tostring(n)
    lua_pushstring(L, "tostring");
    lua_pushcfunction(L, lua_err_tostring);
    lua_settable(L, -3);
    lua_setglobal(L, "err");
    printf("lua_set_globals finished\n");
}
