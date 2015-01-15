#include <lua.h>

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

void lua_err_init(lua_State *L) {
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
}
