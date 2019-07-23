module libssh.types;

alias int32_t = int;
alias uint32_t = uint;
alias uint16_t = ushort;
alias uint8_t = ubyte;
alias uint64_t = ulong;

// unusable struct
//struct ssh_counter_struct {
//    uint64_t in_bytes;
//    uint64_t out_bytes;
//    uint64_t in_packets;
//    uint64_t out_packets;
//}

alias ssh_counter      = void*; // ssh_counter_struct*;

alias ssh_agent        = void*; // ssh_agent_struct*;
alias ssh_buffer       = void*; // ssh_buffer_struct*;
alias ssh_channel      = void*; // ssh_channel_struct*;
alias ssh_message      = void*; // ssh_message_struct*;
alias ssh_pcap_file    = void*; // ssh_pcap_file_struct*;
alias ssh_key          = void*; // ssh_key_struct*;
alias ssh_scp          = void*; // ssh_scp_struct*;
alias ssh_session      = void*; // ssh_session_struct*;
alias ssh_string       = void*; // ssh_string_struct*;
alias ssh_event        = void*; // ssh_event_struct*;
alias ssh_connector    = void*; // ssh_connector_struct*;
alias ssh_gssapi_creds = void*;

version (Windows)
{
    public import core.sys.windows.winsock2 : timeval, fd_set, SOCKET;

    enum socket_t : SOCKET { INVALID_SOCKET }
    alias mode_t = ushort;
}
version (Posix)
{
    public import core.sys.posix.sys.types : mode_t;
    public import core.sys.posix.sys.time : timeval;
    public import core.sys.posix.sys.select : fd_set;

    enum socket_t : int32_t { init = -1 }
}

enum ssh_kex_types_e {
    SSH_KEX=0,
    SSH_HOSTKEYS,
    SSH_CRYPT_C_S,
    SSH_CRYPT_S_C,
    SSH_MAC_C_S,
    SSH_MAC_S_C,
    SSH_COMP_C_S,
    SSH_COMP_S_C,
    SSH_LANG_C_S,
    SSH_LANG_S_C
}

enum SSH_CRYPT = 2;
enum SSH_MAC = 3;
enum SSH_COMP = 4;
enum SSH_LANG = 5;

enum ssh_auth_e {
    SSH_AUTH_SUCCESS=0,
    SSH_AUTH_DENIED,
    SSH_AUTH_PARTIAL,
    SSH_AUTH_INFO,
    SSH_AUTH_AGAIN,
    SSH_AUTH_ERROR=-1
}

enum SSH_AUTH_METHOD_UNKNOWN = 0;
enum SSH_AUTH_METHOD_NONE = 0x0001;
enum SSH_AUTH_METHOD_PASSWORD = 0x0002;
enum SSH_AUTH_METHOD_PUBLICKEY = 0x0004;
enum SSH_AUTH_METHOD_HOSTBASED = 0x0008;
enum SSH_AUTH_METHOD_INTERACTIVE = 0x0010;
enum SSH_AUTH_METHOD_GSSAPI_MIC = 0x0020;

/* messages */
enum ssh_requests_e {
    SSH_REQUEST_AUTH=1,
    SSH_REQUEST_CHANNEL_OPEN,
    SSH_REQUEST_CHANNEL,
    SSH_REQUEST_SERVICE,
    SSH_REQUEST_GLOBAL
}

enum ssh_channel_type_e {
    SSH_CHANNEL_UNKNOWN=0,
    SSH_CHANNEL_SESSION,
    SSH_CHANNEL_DIRECT_TCPIP,
    SSH_CHANNEL_FORWARDED_TCPIP,
    SSH_CHANNEL_X11,
    SSH_CHANNEL_AUTH_AGENT
}

enum ssh_channel_requests_e {
    SSH_CHANNEL_REQUEST_UNKNOWN=0,
    SSH_CHANNEL_REQUEST_PTY,
    SSH_CHANNEL_REQUEST_EXEC,
    SSH_CHANNEL_REQUEST_SHELL,
    SSH_CHANNEL_REQUEST_ENV,
    SSH_CHANNEL_REQUEST_SUBSYSTEM,
    SSH_CHANNEL_REQUEST_WINDOW_CHANGE,
    SSH_CHANNEL_REQUEST_X11
}

enum ssh_global_requests_e {
    SSH_GLOBAL_REQUEST_UNKNOWN=0,
    SSH_GLOBAL_REQUEST_TCPIP_FORWARD,
    SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD,
    SSH_GLOBAL_REQUEST_KEEPALIVE
}

enum ssh_publickey_state_e {
    SSH_PUBLICKEY_STATE_ERROR=-1,
    SSH_PUBLICKEY_STATE_NONE=0,
    SSH_PUBLICKEY_STATE_VALID=1,
    SSH_PUBLICKEY_STATE_WRONG=2
}

/* Status flags */
/** Socket is closed */
enum SSH_CLOSED = 0x01;
/** Reading to socket won't block */
enum SSH_READ_PENDING = 0x02;
/** Session was closed due to an error */
enum SSH_CLOSED_ERROR = 0x04;
/** Output buffer not empty */
enum SSH_WRITE_PENDING = 0x08;

enum ssh_server_known_e {
    SSH_SERVER_ERROR=-1,
    SSH_SERVER_NOT_KNOWN=0,
    SSH_SERVER_KNOWN_OK,
    SSH_SERVER_KNOWN_CHANGED,
    SSH_SERVER_FOUND_OTHER,
    SSH_SERVER_FILE_NOT_FOUND
}

enum ssh_known_hosts_e {
    /**
     * There had been an error checking the host.
     */
    SSH_KNOWN_HOSTS_ERROR = -2,

    /**
     * The known host file does not exist. The host is thus unknown. File will
     * be created if host key is accepted.
     */
    SSH_KNOWN_HOSTS_NOT_FOUND = -1,

    /**
     * The server is unknown. User should confirm the public key hash is
     * correct.
     */
    SSH_KNOWN_HOSTS_UNKNOWN = 0,

    /**
     * The server is known and has not changed.
     */
    SSH_KNOWN_HOSTS_OK,

    /**
     * The server key has changed. Either you are under attack or the
     * administrator changed the key. You HAVE to warn the user about a
     * possible attack.
     */
    SSH_KNOWN_HOSTS_CHANGED,

    /**
     * The server gave use a key of a type while we had an other type recorded.
     * It is a possible attack.
     */
    SSH_KNOWN_HOSTS_OTHER,
}

/* errors */

enum ssh_error_types_e {
    SSH_NO_ERROR=0,
    SSH_REQUEST_DENIED,
    SSH_FATAL,
    SSH_EINTR
}

/* some types for keys */
enum ssh_keytypes_e {
    SSH_KEYTYPE_UNKNOWN=0,
    SSH_KEYTYPE_DSS=1,
    SSH_KEYTYPE_RSA,
    SSH_KEYTYPE_RSA1,
    SSH_KEYTYPE_ECDSA,
    SSH_KEYTYPE_ED25519,
    SSH_KEYTYPE_DSS_CERT01,
    SSH_KEYTYPE_RSA_CERT01
}

enum ssh_keycmp_e {
    SSH_KEY_CMP_PUBLIC = 0,
    SSH_KEY_CMP_PRIVATE
}

enum SSH_ADDRSTRLEN = 46;

struct ssh_knownhosts_entry {
    char *hostname;
    char *unparsed;
    ssh_key publickey;
    char *comment;
}

/* Error return codes */
enum SSH_OK = 0;     /* No error */
enum SSH_ERROR = -1; /* Error of some kind */
enum SSH_AGAIN = -2; /* The nonblocking call must be repeated */
enum SSH_EOF = -127; /* We have already a eof */

enum {
    /** No logging at all
     */
    SSH_LOG_NOLOG=0,
    /** Only warnings
     */
    SSH_LOG_WARNING,
    /** High level protocol information
     */
    SSH_LOG_PROTOCOL,
    /** Lower level protocol infomations, packet level
     */
    SSH_LOG_PACKET,
    /** Every function path
     */
    SSH_LOG_FUNCTIONS
}

enum SSH_LOG_NONE = 0; /** No logging at all */
enum SSH_LOG_WARN = 1; /** Show only warnings */
enum SSH_LOG_INFO = 2; /** Get some information what's going on */
enum SSH_LOG_DEBUG = 3; /** Get detailed debuging information **/
enum SSH_LOG_TRACE = 4; /** Get trace output, packet information, ... */

enum ssh_options_e {
  SSH_OPTIONS_HOST,
  SSH_OPTIONS_PORT,
  SSH_OPTIONS_PORT_STR,
  SSH_OPTIONS_FD,
  SSH_OPTIONS_USER,
  SSH_OPTIONS_SSH_DIR,
  SSH_OPTIONS_IDENTITY,
  SSH_OPTIONS_ADD_IDENTITY,
  SSH_OPTIONS_KNOWNHOSTS,
  SSH_OPTIONS_TIMEOUT,
  SSH_OPTIONS_TIMEOUT_USEC,
  SSH_OPTIONS_SSH1,
  SSH_OPTIONS_SSH2,
  SSH_OPTIONS_LOG_VERBOSITY,
  SSH_OPTIONS_LOG_VERBOSITY_STR,
  SSH_OPTIONS_CIPHERS_C_S,
  SSH_OPTIONS_CIPHERS_S_C,
  SSH_OPTIONS_COMPRESSION_C_S,
  SSH_OPTIONS_COMPRESSION_S_C,
  SSH_OPTIONS_PROXYCOMMAND,
  SSH_OPTIONS_BINDADDR,
  SSH_OPTIONS_STRICTHOSTKEYCHECK,
  SSH_OPTIONS_COMPRESSION,
  SSH_OPTIONS_COMPRESSION_LEVEL,
  SSH_OPTIONS_KEY_EXCHANGE,
  SSH_OPTIONS_HOSTKEYS,
  SSH_OPTIONS_GSSAPI_SERVER_IDENTITY,
  SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY,
  SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
  SSH_OPTIONS_HMAC_C_S,
  SSH_OPTIONS_HMAC_S_C,
  SSH_OPTIONS_PASSWORD_AUTH,
  SSH_OPTIONS_PUBKEY_AUTH,
  SSH_OPTIONS_KBDINT_AUTH,
  SSH_OPTIONS_GSSAPI_AUTH,
  SSH_OPTIONS_GLOBAL_KNOWNHOSTS,
  SSH_OPTIONS_NODELAY,
  SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
}

enum {
    /** Code is going to write/create remote files */
    SSH_SCP_WRITE,
    /** Code is going to read remote files */
    SSH_SCP_READ,
    SSH_SCP_RECURSIVE=0x10
}

enum ssh_scp_request_types {
    /** A new directory is going to be pulled */
    SSH_SCP_REQUEST_NEWDIR=1,
    /** A new file is going to be pulled */
    SSH_SCP_REQUEST_NEWFILE,
    /** End of requests */
    SSH_SCP_REQUEST_EOF,
    /** End of directory */
    SSH_SCP_REQUEST_ENDDIR,
    /** Warning received */
    SSH_SCP_REQUEST_WARNING
}

enum ssh_connector_flags_e {
    /** Only the standard stream of the channel */
    SSH_CONNECTOR_STDOUT = 1,
    /** Only the exception stream of the channel */
    SSH_CONNECTOR_STDERR = 2,
    /** Merge both standard and exception streams */
    SSH_CONNECTOR_BOTH = 3
}

enum ssh_publickey_hash_type {
    SSH_PUBLICKEY_HASH_SHA1,
    SSH_PUBLICKEY_HASH_MD5,
    SSH_PUBLICKEY_HASH_SHA256
}

extern (C)
{
    /**
    * @brief SSH authentication callback.
    *
    * @param prompt        Prompt to be displayed.
    * @param buf           Buffer to save the password. You should null-terminate it.
    * @param len           Length of the buffer.
    * @param echo          Enable or disable the echo of what you type.
    * @param verify        Should the password be verified?
    * @param userdata      Userdata to be passed to the callback function. Useful
    *                      for GUI applications.
    *
    * @return              0 on success, < 0 on error.
    */
    alias ssh_auth_callback = int function(const char* prompt, char* buf, size_t len,
        int echo, int verify, void* userdata);

    alias ssh_event_callback = int function(socket_t fd, int revents, void* userdata);
}