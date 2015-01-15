#include <lua.h>
#include <stdbool.h>

typedef struct {
    bool proxy;
    size_t size;
    char *data;
} lua_Buffer;

lua_Buffer *buffer_proxy(lua_State *L, void *target, size_t size);
