#include <sys/mman.h>

#include "lua.h"
#include "qemu.h"

typedef struct {
    void *cpu_env;
    int num;
    abi_long args[8];
} syscall_args;

typedef struct {
    abi_long addr, len;
} syscall_map;

static int orig_syscall = 0;
static syscall_args orig_syscall_args = {0};
static syscall_map syscall_munmap[8] = {{0}};

static abi_long lua_arbitrary_param(lua_State *L, int n, abi_long def) {
    int type = lua_type(L, n);
    int len;
    switch (type) {
        case LUA_TNIL: return 0;
        case LUA_TNUMBER: return (abi_long)lua_tonumber(L, n);
        case LUA_TSTRING:
            len = lua_rawlen(L, n);
            abi_long tmp = target_mmap(0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
            memcpy((void *)g2h(tmp), lua_tostring(L, n), len);
            syscall_munmap[n - 1].addr = tmp;
            syscall_munmap[n - 1].len = len;
            return tmp;
        case LUA_TNONE:
            return def;
        default:
            fprintf(stderr, "unsupported lua type: %s\n", lua_typename(L, type));
            return def;
    }
}

static int lua_syscall_orig(lua_State *L) {
    if (orig_syscall != 0) {
        syscall_args *sargs = &orig_syscall_args;
        abi_long args[8];
        int i, ret;
        for (i = 0; i < 8; i++) {
            args[i] = lua_arbitrary_param(L, i + 1, sargs->args[i]);
        }
        ret = do_syscall_nolua(sargs->cpu_env, sargs->num,
                               args[0], args[1], args[2], args[3],
                               args[4], args[5], args[6], args[7]);
        lua_pushnumber(L, ret);
        for (i = 0; i < 8; i++) {
            syscall_map *m = &syscall_munmap[i];
            if (m->addr) {
                target_munmap(m->addr, m->len);
                m->addr = 0;
                m->len = 0;
            }
        }
        return 1;
    }
    return 0;
}

abi_long lua_hook_syscall(
        void *cpu_env, int num, abi_long a1,
        abi_long a2, abi_long a3, abi_long a4,
        abi_long a5, abi_long a6, abi_long a7,
        abi_long a8) {
    int ret;
    orig_syscall = 1;
    syscall_args *a = &orig_syscall_args;
    a->cpu_env = cpu_env;
    a->num = num;
    a->args[0] = a1, a->args[1] = a2, a->args[2] = a3, a->args[3] = a4;
    a->args[4] = a5, a->args[5] = a6, a->args[6] = a7, a->args[7] = a8;
    lua_State *L = lua_state;
    switch (num) {
        case TARGET_NR_open:
            lua_getglobal(L, "open");
            if (!lua_isfunction(L, -1)) {
                lua_pop(L, -1);
            } else {
                lua_pushstring(L, g2h(a1));
                lua_pushnumber(L, a2);
                lua_pushnumber(L, a3);
                lua_call(L, 3, 1);
                int ret = lua_tonumber(L, -1);
                lua_pop(L, -1);
                return ret;
            }
            break;
        case TARGET_NR_setsockopt:
            lua_getglobal(L, "setsockopt");
            if (!lua_isfunction(L, -1)) {
                lua_pop(L, -1);
            } else {
                lua_pushnumber(L, a1);
                lua_pushnumber(L, a2);
                lua_pushnumber(L, a3);
                lua_call(L, 3, 1);
                int ret = lua_tonumber(L, -1);
                lua_pop(L, -1);
                return ret;
            }
            break;
        case TARGET_NR_bind:
            lua_getglobal(L, "bind");
            if (!lua_isfunction(L, -1)) {
                lua_pop(L, -1);
            } else {
                lua_pushnumber(L, a1);
                lua_call(L, 1, 1);
                int ret = lua_tonumber(L, -1);
                lua_pop(L, -1);
                return ret;
            }
            break;
        case TARGET_NR_shmget:
            lua_getglobal(L, "shmget");
            if (!lua_isfunction(L, -1)) {
                lua_pop(L, -1);
            } else {
                lua_pushnumber(L, a1);
                lua_pushnumber(L, a2);
                lua_pushnumber(L, a3);
                lua_call(L, 3, 1);
                int ret = lua_tonumber(L, -1);
                lua_pop(L, -1);
                return ret;
            }
            break;
        case TARGET_NR_shmctl:
            lua_getglobal(L, "shmctl");
            if (!lua_isfunction(L, -1)) {
                lua_pop(L, -1);
            } else {
                lua_pushnumber(L, a1);
                lua_pushnumber(L, a2);
                lua_pushnumber(L, a3);
                lua_call(L, 3, 1);
                int ret = lua_tonumber(L, -1);
                lua_pop(L, -1);
                return ret;
            }
            break;
        case TARGET_NR_shmat:
            lua_getglobal(L, "shmat");
            if (!lua_isfunction(L, -1)) {
                lua_pop(L, -1);
            } else {
                lua_pushnumber(L, a1);
                lua_pushnumber(L, a2);
                lua_pushnumber(L, a3);
                lua_call(L, 3, 1);
                int ret = lua_tonumber(L, -1);
                lua_pop(L, -1);
                return ret;
            }
            break;
        case TARGET_NR_connect:
            lua_getglobal(L, "connect");
            if (!lua_isfunction(L, -1)) {
                lua_pop(L, -1);
            } else {
                lua_pushnumber(L, a1);
                lua_pushnumber(L, a2);
                lua_pushnumber(L, a3);
                lua_call(L, 3, 1);
                int ret = lua_tonumber(L, -1);
                lua_pop(L, -1);
                return ret;
            }
            break;
        default:
            break;
    }
    ret = do_syscall_nolua(cpu_env, num, a1, a2, a3, a4, a5, a6, a7, a8);
    orig_syscall = 0;
    return ret;
}

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

    lua_register(L, "orig", lua_syscall_orig);
}
