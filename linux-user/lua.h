#ifndef QEMU_LUA_H
#define QEMU_LUA_H

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include "lua_syscall.h"

extern lua_State *lua_state;
extern int lua_init(const char *);
#endif
