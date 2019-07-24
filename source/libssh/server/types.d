module libssh.server.types;

import libssh.types;

enum ssh_bind_options_e {
    SSH_BIND_OPTIONS_BINDADDR,
    SSH_BIND_OPTIONS_BINDPORT,
    SSH_BIND_OPTIONS_BINDPORT_STR,
    SSH_BIND_OPTIONS_HOSTKEY,
    SSH_BIND_OPTIONS_DSAKEY,
    SSH_BIND_OPTIONS_RSAKEY,
    SSH_BIND_OPTIONS_BANNER,
    SSH_BIND_OPTIONS_LOG_VERBOSITY,
    SSH_BIND_OPTIONS_LOG_VERBOSITY_STR,
    SSH_BIND_OPTIONS_ECDSAKEY,
    SSH_BIND_OPTIONS_IMPORT_KEY
}

enum SSH_BIND_OPTION
{
    BINDADDR          = ssh_bind_options_e.SSH_BIND_OPTIONS_BINDADDR,
    BINDPORT          = ssh_bind_options_e.SSH_BIND_OPTIONS_BINDPORT,
    BINDPORT_STR      = ssh_bind_options_e.SSH_BIND_OPTIONS_BINDPORT_STR,
    HOSTKEY           = ssh_bind_options_e.SSH_BIND_OPTIONS_HOSTKEY,
    DSAKEY            = ssh_bind_options_e.SSH_BIND_OPTIONS_DSAKEY,
    RSAKEY            = ssh_bind_options_e.SSH_BIND_OPTIONS_RSAKEY,
    BANNER            = ssh_bind_options_e.SSH_BIND_OPTIONS_BANNER,
    LOG_VERBOSITY     = ssh_bind_options_e.SSH_BIND_OPTIONS_LOG_VERBOSITY,
    LOG_VERBOSITY_STR = ssh_bind_options_e.SSH_BIND_OPTIONS_LOG_VERBOSITY_STR,
    ECDSAKEY          = ssh_bind_options_e.SSH_BIND_OPTIONS_ECDSAKEY,
    IMPORT_KEY        = ssh_bind_options_e.SSH_BIND_OPTIONS_IMPORT_KEY
}

alias ssh_bind = void*;

// not used directly, only pointer
//struct ssh_bind_callbacks_struct {
//  /** DON'T SET THIS use ssh_callbacks_init() instead. */
//  size_t size;
//  /** A new connection is available. */
//  ssh_bind_incoming_connection_callback incoming_connection;
//};
alias ssh_bind_callbacks = void*;

extern (C)
{
    /* Callback functions */
    
    /**
    * @brief Incoming connection callback. This callback is called when a ssh_bind
    *        has a new incoming connection.
    * @param sshbind Current sshbind session handler
    * @param userdata Userdata to be passed to the callback function.
    */
    alias ssh_bind_incoming_connection_callback = void function(ssh_bind sshbind, void* userdata);

    alias ssh_bind_message_callback = int function(ssh_session session, ssh_message msg, void* data);
}