module libssh.ctlink;

import libssh.types;

version (libssh_rtload) {}
else:

int ssh_blocking_flush(ssh_session session, int timeout);
ssh_channel ssh_channel_accept_x11(ssh_channel channel, int timeout_ms);
int ssh_channel_change_pty_size(ssh_channel channel, int cols, int rows);
int ssh_channel_close(ssh_channel channel);
void ssh_channel_free(ssh_channel channel);
int ssh_channel_get_exit_status(ssh_channel channel);
ssh_session ssh_channel_get_session(ssh_channel channel);
int ssh_channel_is_closed(ssh_channel channel);
int ssh_channel_is_eof(ssh_channel channel);
int ssh_channel_is_open(ssh_channel channel);
ssh_channel ssh_channel_new(ssh_session session);
int ssh_channel_open_auth_agent(ssh_channel channel);
int ssh_channel_open_forward(ssh_channel channel, const char* remotehost,
    int remoteport, const char* sourcehost, int localport);
int ssh_channel_open_session(ssh_channel channel);
int ssh_channel_open_x11(ssh_channel channel, const char* orig_addr, int orig_port);
int ssh_channel_poll(ssh_channel channel, int is_stderr);
int ssh_channel_poll_timeout(ssh_channel channel, int timeout, int is_stderr);
int ssh_channel_read(ssh_channel channel, void* dest, uint32_t count, int is_stderr);
int ssh_channel_read_timeout(ssh_channel channel, void* dest, uint32_t count, int is_stderr, int timeout_ms);
int ssh_channel_read_nonblocking(ssh_channel channel, void* dest, uint32_t count, int is_stderr);
int ssh_channel_request_env(ssh_channel channel, const char* name, const char* value);
int ssh_channel_request_exec(ssh_channel channel, const char *cmd);
int ssh_channel_request_pty(ssh_channel channel);
int ssh_channel_request_pty_size(ssh_channel channel, const char* term, int cols, int rows);
int ssh_channel_request_shell(ssh_channel channel);
int ssh_channel_request_send_signal(ssh_channel channel, const char* signum);
int ssh_channel_request_send_break(ssh_channel channel, uint32_t length);
int ssh_channel_request_sftp(ssh_channel channel);
int ssh_channel_request_subsystem(ssh_channel channel, const char* subsystem);
int ssh_channel_request_x11(ssh_channel channel, int single_connection, const char* protocol, const char* cookie, int screen_number);
int ssh_channel_request_auth_agent(ssh_channel channel);
int ssh_channel_send_eof(ssh_channel channel);
int ssh_channel_select(ssh_channel* readchans, ssh_channel* writechans, ssh_channel* exceptchans, timeval* timeout);
void ssh_channel_set_blocking(ssh_channel channel, int blocking);
void ssh_channel_set_counter(ssh_channel channel, ssh_counter counter);
int ssh_channel_write(ssh_channel channel, const void *data, uint32_t len);
int ssh_channel_write_stderr(ssh_channel channel, const void* data, uint32_t len);
uint32_t ssh_channel_window_size(ssh_channel channel);

char* ssh_basename (const char* path);
void ssh_clean_pubkey_hash(ubyte** hash);
int ssh_connect(ssh_session session);

ssh_connector ssh_connector_new(ssh_session session);
void ssh_connector_free(ssh_connector connector);
int ssh_connector_set_in_channel(ssh_connector connector, ssh_channel channel, ssh_connector_flags_e flags);
int ssh_connector_set_out_channel(ssh_connector connector, ssh_channel channel, ssh_connector_flags_e flags);
void ssh_connector_set_in_fd(ssh_connector connector, socket_t fd);
void ssh_connector_set_out_fd(ssh_connector connector, socket_t fd);

const char* ssh_copyright(void);
void ssh_disconnect(ssh_session session);
char* ssh_dirname (const char *path);
int ssh_finalize(void);

/* REVERSE PORT FORWARDING */
ssh_channel ssh_channel_accept_forward(ssh_session session, int timeout_ms, int* destination_port);
int ssh_channel_cancel_forward(ssh_session session, const char* address, int port);
int ssh_channel_listen_forward(ssh_session session, const char* address, int port, int* bound_port);

void ssh_free(ssh_session session);
const char* ssh_get_disconnect_message(ssh_session session);
const char* ssh_get_error(void* error);
int ssh_get_error_code(void* error);
socket_t ssh_get_fd(ssh_session session);
char* ssh_get_hexa(const ubyte* what, size_t len);
char* ssh_get_issue_banner(ssh_session session);
int ssh_get_openssh_version(ssh_session session);

int ssh_get_server_publickey(ssh_session session, ssh_key *key);

int ssh_get_publickey_hash(const ssh_key key, ssh_publickey_hash_type type, ubyte** hash, size_t* hlen);

/* DEPRECATED FUNCTIONS */
deprecated int ssh_get_pubkey_hash(ssh_session session, ubyte** hash);
deprecated ssh_channel ssh_forward_accept(ssh_session session, int timeout_ms);
deprecated int ssh_forward_cancel(ssh_session session, const char* address, int port);
deprecated int ssh_forward_listen(ssh_session session, const char* address, int port, int* bound_port);
deprecated int ssh_get_publickey(ssh_session session, ssh_key* key);


int ssh_get_random(void* where, int len, int strong);
int ssh_get_version(ssh_session session);
int ssh_get_status(ssh_session session);
int ssh_get_poll_flags(ssh_session session);
int ssh_init();
int ssh_is_blocking(ssh_session session);
int ssh_is_connected(ssh_session session);
int ssh_is_server_known(ssh_session session);

/* KNOWN HOSTS */
void ssh_knownhosts_entry_free(ssh_knownhosts_entry* entry);

int ssh_known_hosts_parse_line(const char* host, const char* line, ssh_knownhosts_entry** entry);
ssh_known_hosts_e ssh_session_has_known_hosts_entry(ssh_session session);

int ssh_session_export_known_hosts_entry(ssh_session session, char** pentry_string);
int ssh_session_update_known_hosts(ssh_session session);

enum ssh_known_hosts_e ssh_session_get_known_hosts_entry(ssh_session session, ssh_knownhosts_entry** pentry);
enum ssh_known_hosts_e ssh_session_is_known_server(ssh_session session);

/* LOGGING */
int ssh_set_log_level(int level);
int ssh_get_log_level();
void* ssh_get_log_userdata();
int ssh_set_log_userdata(void* data);

//void _ssh_log(int verbosity, const char *func, const char* format, ...) PRINTF_ATTRIBUTE(3, 4);

/* legacy */
//deprecated void ssh_log(ssh_session session, int prioriry, const char* format, ...) PRINTF_ATTRIBUTE(3, 4);

ssh_channel ssh_message_channel_request_open_reply_accept(ssh_message msg);
int ssh_message_channel_request_reply_success(ssh_message msg);
void ssh_message_free(ssh_message msg);
ssh_message ssh_message_get(ssh_session session);
int ssh_message_subtype(ssh_message msg);
int ssh_message_type(ssh_message msg);
int ssh_mkdir (const char* pathname, mode_t mode);
ssh_session ssh_new();

int ssh_options_copy(ssh_session src, ssh_session* dest);
int ssh_options_getopt(ssh_session session, int* argcptr, char** argv);
int ssh_options_parse_config(ssh_session session, const char* filename);
int ssh_options_set(ssh_session session, ssh_options_e type, const void* value);
int ssh_options_get(ssh_session session, ssh_options_e type, char** value);
int ssh_options_get_port(ssh_session session, uint* port_target);
int ssh_pcap_file_close(ssh_pcap_file pcap);
void ssh_pcap_file_free(ssh_pcap_file pcap);
ssh_pcap_file ssh_pcap_file_new();
int ssh_pcap_file_open(ssh_pcap_file pcap, const char* filename);

ssh_key ssh_key_new();
void ssh_key_free (ssh_key key);
enum ssh_keytypes_e ssh_key_type(const ssh_key key);
const char* ssh_key_type_to_char(ssh_keytypes_e type);
enum ssh_keytypes_e ssh_key_type_from_name(const char* name);
int ssh_key_is_public(const ssh_key k);
int ssh_key_is_private(const ssh_key k);
int ssh_key_cmp(const ssh_key k1, const ssh_key k2, ssh_keycmp_e what);

int ssh_pki_generate(ssh_keytypes_e type, int parameter, ssh_key *pkey);
int ssh_pki_import_privkey_base64(const char* b64_key, const char* passphrase, ssh_auth_callback auth_fn, void* auth_data, ssh_key* pkey);
int ssh_pki_export_privkey_base64(const ssh_key privkey, const char* passphrase, ssh_auth_callback auth_fn, void* auth_data, char** b64_key);
int ssh_pki_import_privkey_file(const char* filename, const char* passphrase, ssh_auth_callback auth_fn, void* auth_data, ssh_key* pkey);
int ssh_pki_export_privkey_file(const ssh_key privkey, const char* passphrase, ssh_auth_callback auth_fn, void* auth_data, const char* filename);

int ssh_pki_copy_cert_to_privkey(const ssh_key cert_key, ssh_key privkey);

int ssh_pki_import_pubkey_base64(const char* b64_key, ssh_keytypes_e type, ssh_key* pkey);
int ssh_pki_import_pubkey_file(const char* filename, ssh_key* pkey);

int ssh_pki_import_cert_base64(const char* b64_cert, ssh_keytypes_e type, ssh_key* pkey);
int ssh_pki_import_cert_file(const char* filename, ssh_key* pkey);

int ssh_pki_export_privkey_to_pubkey(const ssh_key privkey, ssh_key* pkey);
int ssh_pki_export_pubkey_base64(const ssh_key key, char** b64_key);
int ssh_pki_export_pubkey_file(const ssh_key key, const char* filename);

const char* ssh_pki_key_ecdsa_name(const ssh_key key);

char* ssh_get_fingerprint_hash(ssh_publickey_hash_type type, ubyte* hash, size_t len);
void ssh_print_hash(ssh_publickey_hash_type type, ubyte* hash, size_t len);
void ssh_print_hexa(const char* descr, const ubyte* what, size_t len);
int ssh_send_ignore(ssh_session session, const char* data);
int ssh_send_debug(ssh_session session, const char* message, int always_display);
void ssh_gssapi_set_creds(ssh_session session, const ssh_gssapi_creds creds);
int ssh_scp_accept_request(ssh_scp scp);
int ssh_scp_close(ssh_scp scp);
int ssh_scp_deny_request(ssh_scp scp, const char* reason);
void ssh_scp_free(ssh_scp scp);
int ssh_scp_init(ssh_scp scp);
int ssh_scp_leave_directory(ssh_scp scp);
ssh_scp ssh_scp_new(ssh_session session, int mode, const char* location);
int ssh_scp_pull_request(ssh_scp scp);
int ssh_scp_push_directory(ssh_scp scp, const char* dirname, int mode);
int ssh_scp_push_file(ssh_scp scp, const char* filename, size_t size, int perms);
int ssh_scp_push_file64(ssh_scp scp, const char* filename, uint64_t size, int perms);
int ssh_scp_read(ssh_scp scp, void* buffer, size_t size);
const char* ssh_scp_request_get_filename(ssh_scp scp);
int ssh_scp_request_get_permissions(ssh_scp scp);
size_t ssh_scp_request_get_size(ssh_scp scp);
uint64_t ssh_scp_request_get_size64(ssh_scp scp);
const char* ssh_scp_request_get_warning(ssh_scp scp);
int ssh_scp_write(ssh_scp scp, const void* buffer, size_t len);
int ssh_select(ssh_channel* channels, ssh_channel* outchannels, socket_t maxfd, fd_set* readfds, timeval* timeout);
int ssh_service_request(ssh_session session, const char* service);
int ssh_set_agent_channel(ssh_session session, ssh_channel channel);
int ssh_set_agent_socket(ssh_session session, socket_t fd);
void ssh_set_blocking(ssh_session session, int blocking);
void ssh_set_counters(ssh_session session, ssh_counter scounter, ssh_counter rcounter);
void ssh_set_fd_except(ssh_session session);
void ssh_set_fd_toread(ssh_session session);
void ssh_set_fd_towrite(ssh_session session);
void ssh_silent_disconnect(ssh_session session);
int ssh_set_pcap_file(ssh_session session, ssh_pcap_file pcapfile);

/* USERAUTH */
int ssh_userauth_none(ssh_session session, const char* username);
int ssh_userauth_list(ssh_session session, const char* username);
int ssh_userauth_try_publickey(ssh_session session, const char* username, const ssh_key pubkey);
int ssh_userauth_publickey(ssh_session session, const char* username, const ssh_key privkey);

version (Windows) {}
else {
    int ssh_userauth_agent(ssh_session session, const char* username);
}

int ssh_userauth_publickey_auto(ssh_session session, const char* username, const char* passphrase);
int ssh_userauth_password(ssh_session session, const char* username, const char* password);

int ssh_userauth_kbdint(ssh_session session, const char* user, const char* submethods);
const char* ssh_userauth_kbdint_getinstruction(ssh_session session);
const char* ssh_userauth_kbdint_getname(ssh_session session);
int ssh_userauth_kbdint_getnprompts(ssh_session session);
const char* ssh_userauth_kbdint_getprompt(ssh_session session, uint i, char* echo);
int ssh_userauth_kbdint_getnanswers(ssh_session session);
const char* ssh_userauth_kbdint_getanswer(ssh_session session, uint i);
int ssh_userauth_kbdint_setanswer(ssh_session session, uint i, const char* answer);
int ssh_userauth_gssapi(ssh_session session);
const char* ssh_version(int req_version);
int ssh_write_knownhost(ssh_session session);
char* ssh_dump_knownhost(ssh_session session);

void ssh_string_burn(ssh_string str);
ssh_string ssh_string_copy(ssh_string str);
void* ssh_string_data(ssh_string str);
int ssh_string_fill(ssh_string str, const void* data, size_t len);
void ssh_string_free(ssh_string str);
ssh_string ssh_string_from_char(const char* what);
size_t ssh_string_len(ssh_string str);
ssh_string ssh_string_new(size_t size);
const char* ssh_string_get_char(ssh_string str);
char* ssh_string_to_char(ssh_string str);
void ssh_string_free_char(char* s);

int ssh_getpass(const char* prompt, char* buf, size_t len, int echo, int verify);

ssh_event ssh_event_new(void);
int ssh_event_add_fd(ssh_event event, socket_t fd, short events, ssh_event_callback cb, void* userdata);
int ssh_event_add_session(ssh_event event, ssh_session session);
int ssh_event_add_connector(ssh_event event, ssh_connector connector);
int ssh_event_dopoll(ssh_event event, int timeout);
int ssh_event_remove_fd(ssh_event event, socket_t fd);
int ssh_event_remove_session(ssh_event event, ssh_session session);
int ssh_event_remove_connector(ssh_event event, ssh_connector connector);
void ssh_event_free(ssh_event event);
const char* ssh_get_clientbanner(ssh_session session);
const char* ssh_get_serverbanner(ssh_session session);
const char* ssh_get_kex_algo(ssh_session session);
const char* ssh_get_cipher_in(ssh_session session);
const char* ssh_get_cipher_out(ssh_session session);
const char* ssh_get_hmac_in(ssh_session session);
const char* ssh_get_hmac_out(ssh_session session);

ssh_buffer ssh_buffer_new(void);
void ssh_buffer_free(ssh_buffer buffer);
int ssh_buffer_reinit(ssh_buffer buffer);
int ssh_buffer_add_data(ssh_buffer buffer, const void* data, uint32_t len);
uint32_t ssh_buffer_get_data(ssh_buffer buffer, void* data, uint32_t requestedlen);
void* ssh_buffer_get(ssh_buffer buffer);
uint32_t ssh_buffer_get_len(ssh_buffer buffer);