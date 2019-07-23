module libssh.api;

public import libssh.types;

version (libssh_rtload)
    public import libssh.rtload;
else
    public import libssh.ctlink;

public import libssh.definefuncs;