module libssh.definefuncs;

import libssh.types;

version (libssh_rtload)
    import libssh.rtload;
else
    import libssh.ctlink;

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