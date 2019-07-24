module libssh.server.funcs;

import libssh.types;

import libssh.server.types;

version (libssh_rtload)
{
    import ssll;
    import libssh.funcs : lib;

    void loadLibSSHServerSymbols(LoadApiSymbolsVerbose verbose = LoadApiSymbolsVerbose.message)
    {
        loadApiSymbols(verbose);
    }
}

import libssh.mix;

mixin(pastFunctions(import("libssh/server/funcs.txt")));