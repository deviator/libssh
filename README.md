# libssh binding

By default used configuration `ctlink` for linking at compile time.
You need instal `libssh` before building your application.

Configuration `rtload` implies that your application need load library
at runtime by `loadLibSSH()` call. It may be useful for cross-compilation
without need target `libssh`. For dynamic loading used `ssll` library.

```d
    version (libssh_rtload)
    {
        loadLibSSH();
        scope (exit) unloadLibSSH();
    }

    auto s = ssh_new();

    ... // other libssh calls
```

Due to the mismatch between C and D direct copy-paste from C examples
don't work, some constants placed as `enum`-lists and has redundant
naming but some not:

```c
// C code
ssh_options_set(session, SSH_OPTIONS_HOST, args[1]);
...
rc = ssh_channel_open_session(channel);
if (rc != SSH_OK) ...
```

```d
// D code
ssh_options_set(session, ssh_options_e.SSH_OPTIONS_HOST, args[1].toStringz);
...
rc = ssh_channel_open_session(channel);
if (rc != SSH_OK) ...
```

For more comforable use added `libssh/dconst.d` file with
definition of library constants.

```d
// D code
ssh_options_set(my_ssh_session, SSH_OPTION.HOST, args[1].toStringz);
...
rc = ssh_channel_open_session(channel);
if (rc != SSH_RETCODE.OK) ...
```

---

Used `libssh` headers from version 0.8.7.