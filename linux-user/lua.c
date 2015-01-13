#include <errno.h>
#include <glob.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lua.h"

lua_State *lua_state;

int lua_init(const char *lua_path) {
    int i, status;
    char *cwd = getcwd(NULL, PATH_MAX);
    if (cwd == NULL) {
        fprintf(stderr, "qemu: in getcwd(): %s\n", strerror(errno));
        return errno;
    }
    if (chdir(lua_path) != 0) {
        return errno;
    }
    lua_state = luaL_newstate();
    if (lua_state == NULL) {
        fprintf(stderr, "qemu: failed to create lua state.\n");
        return 1;
    }
    luaL_openlibs(lua_state);

    glob_t globtmp;
    glob("*.lua", 0, NULL, &globtmp);
    for (i = 0; i < globtmp.gl_pathc; i++) {
        char *path = globtmp.gl_pathv[i];
        status = luaL_loadfile(lua_state, path);
        if (status) {
            fprintf(stderr, "qemu: couldn't load lua script '%s': %s\n", path, lua_tostring(lua_state, -1));
            return 1;
        }
    }
    if (chdir(cwd) != 0) {
        fprintf(stderr, "qemu: error restoring current directory: %s\n", strerror(errno));
        return errno;
    }
    free(cwd);
    status = lua_pcall(lua_state, 0, LUA_MULTRET, 0);
    if (status) {
        fprintf(stderr, "qemu: failed to run lua: %s\n", lua_tostring(lua_state, -1));
        return 1;
    }
    return 0;
}
