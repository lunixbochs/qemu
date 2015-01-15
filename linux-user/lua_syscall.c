#include "qemu.h"
#include "lua.h"
#include "lua_syscall_defs.h"
#include "lua_util.h"

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

static abi_long lua_syscall_param(lua_State *L, int n, abi_long def) {
    int type = lua_type(L, n);
    int len;
    switch (type) {
        case LUA_TNIL: return 0;
        case LUA_TNUMBER: return (abi_long)lua_tonumber(L, n);
        case LUA_TSTRING:
            len = lua_rawlen(L, n);
            void *tmp = target_malloc(len);
            memcpy(tmp, lua_tostring(L, n), len);
            syscall_munmap[n - 1].addr = h2g(tmp);
            syscall_munmap[n - 1].len = len;
            return h2g(tmp);
        case LUA_TUSERDATA: {
            // TODO: need to implement proxy/propagate
            lua_Buffer *buf = luaL_checkudata(L, n, "buffer");
            return h2g(buf->data);
        }
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
            args[i] = lua_syscall_param(L, i + 1, sargs->args[i]);
        }
        ret = do_syscall_nolua(sargs->cpu_env, sargs->num,
                               args[0], args[1], args[2], args[3],
                               args[4], args[5], args[6], args[7]);
        lua_pushnumber(L, ret);
        for (i = 0; i < 8; i++) {
            syscall_map *m = &syscall_munmap[i];
            if (m->addr) {
                target_free(m->addr, m->len);
                m->addr = 0;
                m->len = 0;
            }
        }
        return 1;
    }
    return 0;
}

static int getfunction(lua_State *L, const char *name) {
    if (name == NULL) {
        return false;
    }
    lua_getglobal(L, name);
    if (lua_isfunction(L, -1)) {
        return true;
    } else {
        lua_pop(L, -1);
        return false;
    }
}

static abi_long lua_ret(lua_State *L) {
    int ret = lua_tonumber(L, -1);
    if (lua_isnil(L, -1)) {
        ret = -1;
    }
    lua_pop(L, -1);
    return ret;
}

abi_long lua_hook_syscall(
        void *cpu_env, int num, abi_long a1,
        abi_long a2, abi_long a3, abi_long a4,
        abi_long a5, abi_long a6, abi_long a7,
        abi_long a8) {
    int i, ret;
    abi_long *args;

    orig_syscall = 1;
    syscall_args *a = &orig_syscall_args;
    a->cpu_env = cpu_env;
    a->num = num;
    a->args[0] = a1, a->args[1] = a2, a->args[2] = a3, a->args[3] = a4;
    a->args[4] = a5, a->args[5] = a6, a->args[6] = a7, a->args[7] = a8;
    lua_State *L = lua_state;

    // lua_State will be null if user didn't specify script base path
    // we also want to make sure the syscall is inside our definition range
    int max = sizeof(lua_syscall_defs) / sizeof(lua_syscall_def);
    if (L != NULL && num < max && num >= 0) {
        lua_syscall_def *def = &lua_syscall_defs[num];
        // getfunction() will find a lua function named for our syscall and put it on the stack
        if (def->num == num && getfunction(L, def->name)) {
            switch (num) {
                case TARGET_NR_read:
                    lua_pushnumber(L, a1);
                    buffer_proxy(L, g2h(a2), a3);
                    lua_pushnumber(L, a3);
                    lua_call(L, 3, 1);
                    return lua_ret(L);
                default: {
                    i = 0, args = def->args;
                    while (args[i] && i < 9) {
                        switch (args[i]) {
                            case PTR_T:
                            case NUM_T:
                                lua_pushnumber(L, a->args[i]);
                                break;
                            case STR_T:
                                lua_pushstring(L, g2h(a->args[i]));
                                break;
                            default:
                                lua_pushnil(L);
                                break;
                        }
                        i++;
                    }
                    lua_call(L, i, 1);
                    return lua_ret(L);
                }
            }
        }
    }
    ret = do_syscall_nolua(cpu_env, num, a1, a2, a3, a4, a5, a6, a7, a8);
    orig_syscall = 0;
    return ret;
}

void lua_syscall_init(lua_State *L) {
    lua_register(L, "orig", lua_syscall_orig);
}
