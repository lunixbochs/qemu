#include "lua.h"

void lua_api_init(lua_State *L) {
    lua_buffer_init(L);
    lua_syscall_init(L);
    lua_err_init(L);
}
