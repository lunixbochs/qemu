#include <string.h>

#include "lua.h"
#include "lua_util.h"

lua_Buffer *buffer_proxy(lua_State *L, void *data, size_t size) {
    lua_Buffer *buf = lua_newuserdata(L, sizeof(lua_Buffer));
    buf->proxy = true;
    buf->size = size;
    buf->data = data;
    luaL_setmetatable(L, "buffer");
    return buf;
}

static int buffer_new(lua_State *L) {
    size_t size = luaL_checkint(L, 1);
    lua_Buffer *buf = lua_newuserdata(L, sizeof(lua_Buffer));
    buf->proxy = false;
    buf->size = size;
    buf->data = target_malloc(size);
    luaL_setmetatable(L, "buffer");
    return 1;
}

static lua_Buffer *checkbuffer(lua_State *L, int n) {
    return luaL_checkudata(L, n, "buffer");
}

static int buffer_gc(lua_State *L) {
    lua_Buffer *buf = checkbuffer(L, 1);
    if (!buf->proxy) {
        target_free(buf->data, buf->size);
        buf->data = NULL;
    }
    return 0;
}

static int buffer_len(lua_State *L) {
    lua_Buffer *buf = checkbuffer(L, 1);
    lua_pushnumber(L, buf->size);
    return 1;
}

static int buffer_tostring(lua_State *L) {
    lua_Buffer *buf = checkbuffer(L, 1);
    lua_pushlstring(L, buf->data, buf->size);
    return 1;
}

static int buffer_write(lua_State *L) {
    lua_Buffer *dst = checkbuffer(L, 1);
    int type = lua_type(L, 2);
    switch (type) {
        case LUA_TSTRING: {
            const char *str = luaL_checkstring(L, 2);
            strncpy(dst->data, str, dst->size);
            return 0;
        }
        case LUA_TUSERDATA: {
            lua_Buffer *src = checkbuffer(L, 2);
            memcpy(dst->data, src->data, MIN(dst->size, src->size));
            return 0;
        }
        default:
            return luaL_error(L, "invalid type for buffer.write(): %s", lua_typename(L, type));
    }
}

static int buffer_slice(lua_State *L) {
    lua_Buffer *buf = checkbuffer(L, 1);
    int start = 0;
    size_t end, size;
    if (!lua_isnone(L, 2)) {
        start = luaL_checkint(L, 2) - 1;
    }
    if (!lua_isnone(L, 3)) {
        end = luaL_checkint(L, 3);
    } else {
        end = buf->size - start + 1;
    }
    size = end - start;
    size = MIN(start + size, buf->size);
    if (start < 0 || start > buf->size) {
        return luaL_error(L, "buffer index (%d) out of bounds (%d-%d)", start + 1, 1, buf->size);
    }
    // TODO: give this a weakref to the original buffer so lua won't dealloc it
    buffer_proxy(L, buf->data + start, size);
    return 1;
}

static const luaL_Reg buffer_lib[] = {
    {"new", buffer_new},
    {"__gc", buffer_gc},
    {"__len", buffer_len},
    {"__tostring", buffer_tostring},
    {"slice", buffer_slice},
    {"write", buffer_write},
    {NULL, NULL},
};

void lua_buffer_init(lua_State *L) {
    luaL_newmetatable(L, "buffer");
    luaL_setfuncs(L, buffer_lib, 0);
    lua_pushvalue(L, -1);
    lua_setglobal(L, "buffer");
    lua_setfield(L, -1, "__index");
    lua_getglobal(L, "buffer");
}
