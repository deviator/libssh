import std.stdio;
import std.string : toStringz, fromStringz;

import libssh;
import libssh.dconst;

import libssh.server;

int show_remote_files(ssh_session session)
{
    ssh_channel channel = ssh_channel_new(session);
    if (channel == null) return SSH_RETCODE.ERROR;
    scope (exit) ssh_channel_free(channel);

    int rc = ssh_channel_open_session(channel);
    if (rc != SSH_RETCODE.OK) return rc;
    scope (exit) ssh_channel_close(channel);

    rc = ssh_channel_request_exec(channel, "ls -l");
    if (rc != SSH_RETCODE.OK) return rc;

    char[256] buffer;
    int nbytes = ssh_channel_read(channel, buffer.ptr, buffer.length, 0);
    string res;

    while (nbytes > 0)
    {
        res ~= buffer[0..nbytes];
        nbytes = ssh_channel_read(channel, buffer.ptr, buffer.length, 0);
    }
    writeln(res);

    ssh_channel_send_eof(channel);
    return SSH_RETCODE.OK;
}

int main(string[] args)
{
    version (libssh_rtload)
    {
        loadLibSSH();
        loadLibSSHServerSymbols();
        scope (exit) unloadLibSSH();
    }

    ssh_session my_ssh_session;
    int rc;
    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == null) return -1;
    scope (exit) ssh_free(my_ssh_session);
    ssh_options_set(my_ssh_session, SSH_OPTION.HOST, args[1].toStringz);
    ssh_options_set(my_ssh_session, SSH_OPTION.USER, args[2].toStringz);
    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_RETCODE.OK)
    {
        stderr.writefln("Error connecting to localhost: %s",
                        ssh_get_error(my_ssh_session).fromStringz);
        return -1;
    }
    scope (exit) ssh_disconnect(my_ssh_session);

    // Authenticate ourselves
    rc = ssh_userauth_password(my_ssh_session, null, args[3].toStringz);
    if (rc != SSH_AUTH_RESULT.SUCCESS)
    {
        stderr.writefln("Error authenticating with password: %s",
                        ssh_get_error(my_ssh_session).fromStringz);
        return -1;
    }
    rc = show_remote_files(my_ssh_session);
    if (rc != SSH_RETCODE.OK)
    {
        stderr.writefln("Error while show remote files: %s",
                        ssh_get_error(my_ssh_session).fromStringz);
        return -1;
    }

    return 0;
}