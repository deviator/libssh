module libssh.ctlink;

import libssh.types;

import libssh.mix;

version (libssh_rtload) {}
else:

extern (C)
{
    mixin(appendToAllLines(import("libssh/funcs.txt"), ";"));
}