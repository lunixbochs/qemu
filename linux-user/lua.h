#ifndef QEMU_LUA_H
#define QEMU_LUA_H

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include "lua_buffer.h"
#include "lua_syscall.h"

extern lua_State *lua_state;
extern int lua_init(const char *);
extern void lua_api_init(lua_State *L);
extern void lua_buffer_init(lua_State *L);
extern void lua_err_init(lua_State *L);
extern void lua_syscall_init(lua_State *L);
#endif
