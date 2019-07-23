module libssh.dconst;

import libssh.types;

enum SSH_KEX
{
    KEX       = ssh_kex_types_e.SSH_KEX,
    HOSTKEYS  = ssh_kex_types_e.SSH_HOSTKEYS,
    CRYPT_C_S = ssh_kex_types_e.SSH_CRYPT_C_S,
    CRYPT_S_C = ssh_kex_types_e.SSH_CRYPT_S_C,
    MAC_C_S   = ssh_kex_types_e.SSH_MAC_C_S,
    MAC_S_C   = ssh_kex_types_e.SSH_MAC_S_C,
    COMP_C_S  = ssh_kex_types_e.SSH_COMP_C_S,
    COMP_S_C  = ssh_kex_types_e.SSH_COMP_S_C,
    LANG_C_S  = ssh_kex_types_e.SSH_LANG_C_S,
    LANG_S_C  = ssh_kex_types_e.SSH_LANG_S_C
}

enum SSH_AUTH_RESULT
{
    SUCCESS  = ssh_auth_e.SSH_AUTH_SUCCESS,
    DENIED   = ssh_auth_e.SSH_AUTH_DENIED,
    PARTIAL  = ssh_auth_e.SSH_AUTH_PARTIAL,
    INFO     = ssh_auth_e.SSH_AUTH_INFO,
    AGAIN    = ssh_auth_e.SSH_AUTH_AGAIN,
    ERROR    = ssh_auth_e.SSH_AUTH_ERROR
}

enum SSH_AUTH_METHOD
{
    UNKNOWN     = SSH_AUTH_METHOD_UNKNOWN,
    NONE        = SSH_AUTH_METHOD_NONE,
    PASSWORD    = SSH_AUTH_METHOD_PASSWORD,
    PUBLICKEY   = SSH_AUTH_METHOD_PUBLICKEY,
    HOSTBASED   = SSH_AUTH_METHOD_HOSTBASED,
    INTERACTIVE = SSH_AUTH_METHOD_INTERACTIVE,
    GSSAPI_MIC  = SSH_AUTH_METHOD_GSSAPI_MIC,
}

enum SSH_REQUEST
{
    AUTH         = ssh_requests_e.SSH_REQUEST_AUTH,
    CHANNEL_OPEN = ssh_requests_e.SSH_REQUEST_CHANNEL_OPEN,
    CHANNEL      = ssh_requests_e.SSH_REQUEST_CHANNEL,
    SERVICE      = ssh_requests_e.SSH_REQUEST_SERVICE,
    GLOBAL       = ssh_requests_e.SSH_REQUEST_GLOBAL
}

enum SSH_CHANNEL_TYPE
{
    UNKNOWN         = ssh_channel_type_e.SSH_CHANNEL_UNKNOWN,
    SESSION         = ssh_channel_type_e.SSH_CHANNEL_SESSION,
    DIRECT_TCPIP    = ssh_channel_type_e.SSH_CHANNEL_DIRECT_TCPIP,
    FORWARDED_TCPIP = ssh_channel_type_e.SSH_CHANNEL_FORWARDED_TCPIP,
    X11             = ssh_channel_type_e.SSH_CHANNEL_X11,
    AUTH_AGENT      = ssh_channel_type_e.SSH_CHANNEL_AUTH_AGENT
}

enum SSH_CHANNEL_REQUEST
{
    UNKNOWN       = ssh_channel_requests_e.SSH_CHANNEL_REQUEST_UNKNOWN,
    PTY           = ssh_channel_requests_e.SSH_CHANNEL_REQUEST_PTY,
    EXEC          = ssh_channel_requests_e.SSH_CHANNEL_REQUEST_EXEC,
    SHELL         = ssh_channel_requests_e.SSH_CHANNEL_REQUEST_SHELL,
    ENV           = ssh_channel_requests_e.SSH_CHANNEL_REQUEST_ENV,
    SUBSYSTEM     = ssh_channel_requests_e.SSH_CHANNEL_REQUEST_SUBSYSTEM,
    WINDOW_CHANGE = ssh_channel_requests_e.SSH_CHANNEL_REQUEST_WINDOW_CHANGE,
    X11           = ssh_channel_requests_e.SSH_CHANNEL_REQUEST_X11
}

enum SSH_PUBLICKEY_STATE
{
    ERROR = ssh_publickey_state_e.SSH_PUBLICKEY_STATE_ERROR,
    NONE  = ssh_publickey_state_e.SSH_PUBLICKEY_STATE_NONE,
    VALID = ssh_publickey_state_e.SSH_PUBLICKEY_STATE_VALID,
    WRONG = ssh_publickey_state_e.SSH_PUBLICKEY_STATE_WRONG
}

enum SSH_STATUS_FLAG
{
    CLOSED       = SSH_CLOSED,
    PENDIN       = SSH_READ_PENDING,
    CLOSED_ERROR = SSH_CLOSED_ERROR,
    WRITE_PENDING = SSH_WRITE_PENDING,
}

enum SSH_SERVER_KNOWN
{
    ERROR          = ssh_server_known_e.SSH_SERVER_ERROR,
    NOT_KNOWN      = ssh_server_known_e.SSH_SERVER_NOT_KNOWN,
    OK             = ssh_server_known_e.SSH_SERVER_KNOWN_OK,
    CHANGED        = ssh_server_known_e.SSH_SERVER_KNOWN_CHANGED,
    FOUND_OTHER    = ssh_server_known_e.SSH_SERVER_FOUND_OTHER,
    FILE_NOT_FOUND = ssh_server_known_e.SSH_SERVER_FILE_NOT_FOUND
}

enum SSH_KNOWN_HOSTS
{
    ERROR     = ssh_known_hosts_e.SSH_KNOWN_HOSTS_ERROR,
    NOT_FOUND = ssh_known_hosts_e.SSH_KNOWN_HOSTS_NOT_FOUND,
    UNKNOWN   = ssh_known_hosts_e.SSH_KNOWN_HOSTS_UNKNOWN,
    OK        = ssh_known_hosts_e.SSH_KNOWN_HOSTS_OK,
    CHANGED   = ssh_known_hosts_e.SSH_KNOWN_HOSTS_CHANGED,
    OTHER     = ssh_known_hosts_e.SSH_KNOWN_HOSTS_OTHER,
}

enum SSH_ERROR_TYPE
{
    NO_ERROR       = ssh_error_types_e.SSH_NO_ERROR,
    REQUEST_DENIED = ssh_error_types_e.SSH_REQUEST_DENIED,
    FATAL          = ssh_error_types_e.SSH_FATAL,
    EINTR          = ssh_error_types_e.SSH_EINTR
}

enum SSH_KEYTYPE
{
    UNKNOWN    = ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN,
    DSS        = ssh_keytypes_e.SSH_KEYTYPE_DSS,
    RSA        = ssh_keytypes_e.SSH_KEYTYPE_RSA,
    RSA1       = ssh_keytypes_e.SSH_KEYTYPE_RSA1,
    ECDSA      = ssh_keytypes_e.SSH_KEYTYPE_ECDSA,
    ED25519    = ssh_keytypes_e.SSH_KEYTYPE_ED25519,
    DSS_CERT01 = ssh_keytypes_e.SSH_KEYTYPE_DSS_CERT01,
    RSA_CERT01 = ssh_keytypes_e.SSH_KEYTYPE_RSA_CERT01
}

enum SSH_KEYCMP
{
    PUBLIC  = ssh_keycmp_e.SSH_KEY_CMP_PUBLIC,
    PRIVATE = ssh_keycmp_e.SSH_KEY_CMP_PRIVATE
}

enum SSH_RETCODE
{
    OK    = SSH_OK,
    ERROR = SSH_ERROR,
    AGAIN = SSH_AGAIN,
    EOF   = SSH_EOF
}

enum SSH_LOG
{
    NOLOG     = SSH_LOG_NOLOG,
    WARNING   = SSH_LOG_WARNING,
    PROTOCOL  = SSH_LOG_PROTOCOL,
    PACKET    = SSH_LOG_PACKET,
    FUNCTIONS = SSH_LOG_FUNCTIONS,

    NONE  = SSH_LOG_NONE,
    WARN  = SSH_LOG_WARN,
    INFO  = SSH_LOG_INFO,
    DEBUG = SSH_LOG_DEBUG,
    TRACE = SSH_LOG_TRACE,
}

enum SSH_OPTION
{
    HOST                        = ssh_options_e.SSH_OPTIONS_HOST,
    PORT                        = ssh_options_e.SSH_OPTIONS_PORT,
    PORT_STR                    = ssh_options_e.SSH_OPTIONS_PORT_STR,
    FD                          = ssh_options_e.SSH_OPTIONS_FD,
    USER                        = ssh_options_e.SSH_OPTIONS_USER,
    SSH_DIR                     = ssh_options_e.SSH_OPTIONS_SSH_DIR,
    IDENTITY                    = ssh_options_e.SSH_OPTIONS_IDENTITY,
    ADD_IDENTITY                = ssh_options_e.SSH_OPTIONS_ADD_IDENTITY,
    KNOWNHOSTS                  = ssh_options_e.SSH_OPTIONS_KNOWNHOSTS,
    TIMEOUT                     = ssh_options_e.SSH_OPTIONS_TIMEOUT,
    TIMEOUT_USEC                = ssh_options_e.SSH_OPTIONS_TIMEOUT_USEC,
    SSH1                        = ssh_options_e.SSH_OPTIONS_SSH1,
    SSH2                        = ssh_options_e.SSH_OPTIONS_SSH2,
    LOG_VERBOSITY               = ssh_options_e.SSH_OPTIONS_LOG_VERBOSITY,
    LOG_VERBOSITY_STR           = ssh_options_e.SSH_OPTIONS_LOG_VERBOSITY_STR,
    CIPHERS_C_S                 = ssh_options_e.SSH_OPTIONS_CIPHERS_C_S,
    CIPHERS_S_C                 = ssh_options_e.SSH_OPTIONS_CIPHERS_S_C,
    COMPRESSION_C_S             = ssh_options_e.SSH_OPTIONS_COMPRESSION_C_S,
    COMPRESSION_S_C             = ssh_options_e.SSH_OPTIONS_COMPRESSION_S_C,
    PROXYCOMMAND                = ssh_options_e.SSH_OPTIONS_PROXYCOMMAND,
    BINDADDR                    = ssh_options_e.SSH_OPTIONS_BINDADDR,
    STRICTHOSTKEYCHECK          = ssh_options_e.SSH_OPTIONS_STRICTHOSTKEYCHECK,
    COMPRESSION                 = ssh_options_e.SSH_OPTIONS_COMPRESSION,
    COMPRESSION_LEVEL           = ssh_options_e.SSH_OPTIONS_COMPRESSION_LEVEL,
    KEY_EXCHANGE                = ssh_options_e.SSH_OPTIONS_KEY_EXCHANGE,
    HOSTKEYS                    = ssh_options_e.SSH_OPTIONS_HOSTKEYS,
    GSSAPI_SERVER_IDENTITY      = ssh_options_e.SSH_OPTIONS_GSSAPI_SERVER_IDENTITY,
    GSSAPI_CLIENT_IDENTITY      = ssh_options_e.SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY,
    GSSAPI_DELEGATE_CREDENTIALS = ssh_options_e.SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
    HMAC_C_S                    = ssh_options_e.SSH_OPTIONS_HMAC_C_S,
    HMAC_S_C                    = ssh_options_e.SSH_OPTIONS_HMAC_S_C,
    PASSWORD_AUTH               = ssh_options_e.SSH_OPTIONS_PASSWORD_AUTH,
    PUBKEY_AUTH                 = ssh_options_e.SSH_OPTIONS_PUBKEY_AUTH,
    KBDINT_AUTH                 = ssh_options_e.SSH_OPTIONS_KBDINT_AUTH,
    GSSAPI_AUTH                 = ssh_options_e.SSH_OPTIONS_GSSAPI_AUTH,
    GLOBAL_KNOWNHOSTS           = ssh_options_e.SSH_OPTIONS_GLOBAL_KNOWNHOSTS,
    NODELAY                     = ssh_options_e.SSH_OPTIONS_NODELAY,
    PUBLICKEY_ACCEPTED_TYPES    = ssh_options_e.SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,
}

enum SSH_SCP
{
    WRITE     = SSH_SCP_WRITE,
    READ      = SSH_SCP_READ,
    RECURSIVE = SSH_SCP_RECURSIVE,
}

enum SSH_SCP_REQUEST_TYPE
{
    NEWDIR  = ssh_scp_request_types.SSH_SCP_REQUEST_NEWDIR,
    NEWFILE = ssh_scp_request_types.SSH_SCP_REQUEST_NEWFILE,
    EOF     = ssh_scp_request_types.SSH_SCP_REQUEST_EOF,
    ENDDIR  = ssh_scp_request_types.SSH_SCP_REQUEST_ENDDIR,
    WARNING = ssh_scp_request_types.SSH_SCP_REQUEST_WARNING
}

enum SSH_CONNECTOR_FLAG
{
    STDOUT = ssh_connector_flags_e.SSH_CONNECTOR_STDOUT,
    STDERR = ssh_connector_flags_e.SSH_CONNECTOR_STDERR,
    BOTH   = ssh_connector_flags_e.SSH_CONNECTOR_BOTH
}

enum SSH_PUBLICKEY_HASH_TYPE
{
    SHA1   = ssh_publickey_hash_type.SSH_PUBLICKEY_HASH_SHA1,
    MD5    = ssh_publickey_hash_type.SSH_PUBLICKEY_HASH_MD5,
    SHA256 = ssh_publickey_hash_type.SSH_PUBLICKEY_HASH_SHA256
}