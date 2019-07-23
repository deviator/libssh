module libssh.funcs;

import libssh.types;

import libssh.mix;

private enum funcstxt = import("libssh/funcs.txt");

version (libssh_rtload)
{
    import ssll;

    version (Posix) private enum libNames = ["libssh.so"];
    version (Windows) private enum libNames = ["libssh.dll"];

    package __gshared LibHandler lib;

    void loadLibSSH(string[] names=[])
    {
        import std.exception : enforce;

        if (lib !is null) return;

        foreach (name; libNames~names)
        {
            lib = loadLibrary(name);
            if (lib !is null) break;
        }

        enforce(lib, "can't load libssh");

        loadApiSymbols();
    }

    void unloadLibSSH() { unloadLibrary(lib); }
}

mixin(pastFunctions(import("libssh/funcs.txt")));

pragma(inline, true)
{
    void SSH_KNOWNHOSTS_ENTRY_FREE(ref ssh_knownhosts_entry* e)
    {
        if (e !is null)
        {
            ssh_knownhosts_entry_free(e);
            e = null;
        }
    }

    void SSH_KEY_FREE(ref ssh_key x)
    {
        if (x !is null)
        {
            ssh_key_free(x);
            x = null;
        }
    }

    void SSH_STRING_FREE(ref ssh_string x) 
    {
        if (x !is null)
        {
            ssh_string_free(x);
            x = null;
        }
    }

    void SSH_STRING_FREE_CHAR(ref char* x)
    {
        if (x !is null)
        {
            ssh_string_free_char(x);
            x = null;
        }
    }

    void SSH_BUFFER_FREE(ref ssh_buffer x)
    {
        if (x !is null)
        {
            ssh_buffer_free(x);
            x = null;
        }
    }
}