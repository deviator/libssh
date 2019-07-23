module libssh.api.rtload;

version (libssh_rtload):

import libssh.api.types;

import ssll;

import std.exception : enforce;

version (Posix) private enum libNames = ["libssh.so"];

private __gshared void* lib;

int loadLibSSH(string[] names=[])
{
    if (lib !is null) return 0;

    foreach (name; libNames~names)
    {
        lib = loadLibrary(name);
        if (lib !is null) break;
    }

    enforce(lib, "can't load libssh");

    loadApiSymbols();
    return 0;
}

void unloadLibSSH()
{
    unloadLibrary(lib);
}

mixin apiSymbols;

@api("lib")
{
    mixin(appendToAllLines(import("libssh/funcs.txt"), "{ mixin(rtLib); }"));
}