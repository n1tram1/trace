/* Imports from OpenSSH 8.2p1 */

#ifndef SSHD_H
#define SSHD_H

#include "ssh.h"

typedef enum {
	SYSLOG_LEVEL_QUIET,
	SYSLOG_LEVEL_FATAL,
	SYSLOG_LEVEL_ERROR,
	SYSLOG_LEVEL_INFO,
	SYSLOG_LEVEL_VERBOSE,
	SYSLOG_LEVEL_DEBUG1,
	SYSLOG_LEVEL_DEBUG2,
	SYSLOG_LEVEL_DEBUG3,
	SYSLOG_LEVEL_NOT_SET = -1
}       LogLevel;

typedef enum {
	SYSLOG_FACILITY_DAEMON,
	SYSLOG_FACILITY_USER,
	SYSLOG_FACILITY_AUTH,
#ifdef LOG_AUTHPRIV
	SYSLOG_FACILITY_AUTHPRIV,
#endif
	SYSLOG_FACILITY_LOCAL0,
	SYSLOG_FACILITY_LOCAL1,
	SYSLOG_FACILITY_LOCAL2,
	SYSLOG_FACILITY_LOCAL3,
	SYSLOG_FACILITY_LOCAL4,
	SYSLOG_FACILITY_LOCAL5,
	SYSLOG_FACILITY_LOCAL6,
	SYSLOG_FACILITY_LOCAL7,
	SYSLOG_FACILITY_NOT_SET = -1
}       SyslogFacility;

struct ForwardOptions {
	int	 gateway_ports; /* Allow remote connects to forwarded ports. */
	mode_t	 streamlocal_bind_mask; /* umask for streamlocal binds */
	int	 streamlocal_bind_unlink; /* unlink socket before bind */
};

#define SSH_MAX_HOSTS_FILES	32
#define MAX_CANON_DOMAINS	32
#define PATH_MAX_SUN		(sizeof((struct sockaddr_un *)0)->sun_path)

struct allowed_cname {
	char *source_list;
	char *target_list;
};

typedef struct {
	int     forward_agent;	/* Forward authentication agent. */
	char   *forward_agent_sock_path; /* Optional path of the agent. */
	int     forward_x11;	/* Forward X11 display. */
	int     forward_x11_timeout;	/* Expiration for Cookies */
	int     forward_x11_trusted;	/* Trust Forward X11 display. */
	int     exit_on_forward_failure;	/* Exit if bind(2) fails for -L/-R */
	char   *xauth_location;	/* Location for xauth program */
	struct ForwardOptions fwd_opts;	/* forwarding options */
	int     pubkey_authentication;	/* Try ssh2 pubkey authentication. */
	int     hostbased_authentication;	/* ssh2's rhosts_rsa */
	int     challenge_response_authentication;
					/* Try S/Key or TIS, authentication. */
	int     gss_authentication;	/* Try GSS authentication */
	int     gss_deleg_creds;	/* Delegate GSS credentials */
	int     password_authentication;	/* Try password
						 * authentication. */
	int     kbd_interactive_authentication; /* Try keyboard-interactive auth. */
	char	*kbd_interactive_devices; /* Keyboard-interactive auth devices. */
	int     batch_mode;	/* Batch mode: do not ask for passwords. */
	int     check_host_ip;	/* Also keep track of keys for IP address */
	int     strict_host_key_checking;	/* Strict host key checking. */
	int     compression;	/* Compress packets in both directions. */
	int     tcp_keep_alive;	/* Set SO_KEEPALIVE. */
	int	ip_qos_interactive;	/* IP ToS/DSCP/class for interactive */
	int	ip_qos_bulk;		/* IP ToS/DSCP/class for bulk traffic */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for logging. */

	int     port;		/* Port to connect. */
	int     address_family;
	int     connection_attempts;	/* Max attempts (seconds) before
					 * giving up */
	int     connection_timeout;	/* Max time (seconds) before
					 * aborting connection attempt */
	int     number_of_password_prompts;	/* Max number of password
						 * prompts. */
	char   *ciphers;	/* SSH2 ciphers in order of preference. */
	char   *macs;		/* SSH2 macs in order of preference. */
	char   *hostkeyalgorithms;	/* SSH2 server key types in order of preference. */
	char   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	char   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	char   *hostname;	/* Real host to connect. */
	char   *host_key_alias;	/* hostname alias for .ssh/known_hosts */
	char   *proxy_command;	/* Proxy command for connecting the host. */
	char   *user;		/* User to log in as. */
	int     escape_char;	/* Escape character; -2 = none */

	u_int	num_system_hostfiles;	/* Paths for /etc/ssh/ssh_known_hosts */
	char   *system_hostfiles[SSH_MAX_HOSTS_FILES];
	u_int	num_user_hostfiles;	/* Path for $HOME/.ssh/known_hosts */
	char   *user_hostfiles[SSH_MAX_HOSTS_FILES];
	char   *preferred_authentications;
	char   *bind_address;	/* local socket address for connection to sshd */
	char   *bind_interface;	/* local interface for bind address */
	char   *pkcs11_provider; /* PKCS#11 provider */
	char   *sk_provider; /* Security key provider */
	int	verify_host_key_dns;	/* Verify host key using DNS */

	int     num_identity_files;	/* Number of files for RSA/DSA identities. */
	char   *identity_files[SSH_MAX_IDENTITY_FILES];
	int    identity_file_userprovided[SSH_MAX_IDENTITY_FILES];
	struct sshkey *identity_keys[SSH_MAX_IDENTITY_FILES];

	int	num_certificate_files; /* Number of extra certificates for ssh. */
	char	*certificate_files[SSH_MAX_CERTIFICATE_FILES];
	int	certificate_file_userprovided[SSH_MAX_CERTIFICATE_FILES];
	struct sshkey *certificates[SSH_MAX_CERTIFICATE_FILES];

	int	add_keys_to_agent;
	char   *identity_agent;		/* Optional path to ssh-agent socket */

	/* Local TCP/IP forward requests. */
	int     num_local_forwards;
	struct Forward *local_forwards;

	/* Remote TCP/IP forward requests. */
	int     num_remote_forwards;
	struct Forward *remote_forwards;
	int	clear_forwardings;

	/* stdio forwarding (-W) host and port */
	char   *stdio_forward_host;
	int	stdio_forward_port;

	int	enable_ssh_keysign;
	int64_t rekey_limit;
	int	rekey_interval;
	int	no_host_authentication_for_localhost;
	int	identities_only;
	int	server_alive_interval;
	int	server_alive_count_max;

	int     num_send_env;
	char   **send_env;
	int     num_setenv;
	char   **setenv;

	char	*control_path;
	int	control_master;
	int     control_persist; /* ControlPersist flag */
	int     control_persist_timeout; /* ControlPersist timeout (seconds) */

	int	hash_known_hosts;

	int	tun_open;	/* tun(4) */
	int     tun_local;	/* force tun device (optional) */
	int     tun_remote;	/* force tun device (optional) */

	char	*local_command;
	int	permit_local_command;
	char	*remote_command;
	int	visual_host_key;

	int	request_tty;

	int	proxy_use_fdpass;

	int	num_canonical_domains;
	char	*canonical_domains[MAX_CANON_DOMAINS];
	int	canonicalize_hostname;
	int	canonicalize_max_dots;
	int	canonicalize_fallback_local;
	int	num_permitted_cnames;
	struct allowed_cname permitted_cnames[MAX_CANON_DOMAINS];

	char	*revoked_host_keys;

	int	 fingerprint_hash;

	int	 update_hostkeys; /* one of SSH_UPDATE_HOSTKEYS_* */

	char   *hostbased_key_types;
	char   *pubkey_key_types;

	char   *jump_user;
	char   *jump_host;
	int	jump_port;
	char   *jump_extra;

	char	*ignored_unknown; /* Pattern list of unknown tokens to ignore */
}       Options;

#define MAX_PORTS		256	/* Max # ports. */

#define MAX_SUBSYSTEMS		256	/* Max # subsystems. */

/* permit_root_login */
#define	PERMIT_NOT_SET		-1
#define	PERMIT_NO		0
#define	PERMIT_FORCED_ONLY	1
#define	PERMIT_NO_PASSWD	2
#define	PERMIT_YES		3

/* use_privsep */
#define PRIVSEP_OFF		0
#define PRIVSEP_ON		1
#define PRIVSEP_NOSANDBOX	2

/* PermitOpen */
#define PERMITOPEN_ANY		0
#define PERMITOPEN_NONE		-2

#define DEFAULT_AUTH_FAIL_MAX	6	/* Default for MaxAuthTries */
#define DEFAULT_SESSIONS_MAX	10	/* Default for MaxSessions */

/* Magic name for internal sftp-server */
#define INTERNAL_SFTP_NAME	"internal-sftp"

/* PubkeyAuthOptions flags */
#define PUBKEYAUTH_TOUCH_REQUIRED	1

typedef struct {
	u_int	num_ports;
	u_int	ports_from_cmdline;
	int	ports[MAX_PORTS];	/* Port number to listen on. */
	struct queued_listenaddr *queued_listen_addrs;
	u_int	num_queued_listens;
	struct listenaddr *listen_addrs;
	u_int	num_listen_addrs;
	int	address_family;		/* Address family used by the server. */

	char	*routing_domain;	/* Bind session to routing domain */

	char   **host_key_files;	/* Files containing host keys. */
	int	*host_key_file_userprovided; /* Key was specified by user. */
	u_int	num_host_key_files;     /* Number of files for host keys. */
	char   **host_cert_files;	/* Files containing host certs. */
	u_int	num_host_cert_files;	/* Number of files for host certs. */

	char   *host_key_agent;		/* ssh-agent socket for host keys. */
	char   *pid_file;		/* Where to put our pid */
	int     login_grace_time;	/* Disconnect if no auth in this time
					 * (sec). */
	int     permit_root_login;	/* PERMIT_*, see above */
	int     ignore_rhosts;	/* Ignore .rhosts and .shosts. */
	int     ignore_user_known_hosts;	/* Ignore ~/.ssh/known_hosts
						 * for RhostsRsaAuth */
	int     print_motd;	/* If true, print /etc/motd. */
	int	print_lastlog;	/* If true, print lastlog */
	int     x11_forwarding;	/* If true, permit inet (spoofing) X11 fwd. */
	int     x11_display_offset;	/* What DISPLAY number to start
					 * searching at */
	int     x11_use_localhost;	/* If true, use localhost for fake X11 server. */
	char   *xauth_location;	/* Location of xauth program */
	int	permit_tty;	/* If false, deny pty allocation */
	int	permit_user_rc;	/* If false, deny ~/.ssh/rc execution */
	int     strict_modes;	/* If true, require string home dir modes. */
	int     tcp_keep_alive;	/* If true, set SO_KEEPALIVE. */
	int	ip_qos_interactive;	/* IP ToS/DSCP/class for interactive */
	int	ip_qos_bulk;		/* IP ToS/DSCP/class for bulk traffic */
	char   *ciphers;	/* Supported SSH2 ciphers. */
	char   *macs;		/* Supported SSH2 macs. */
	char   *kex_algorithms;	/* SSH2 kex methods in order of preference. */
	struct ForwardOptions fwd_opts;	/* forwarding options */
	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;	/* Level for system logging. */
	int     hostbased_authentication;	/* If true, permit ssh2 hostbased auth */
	int     hostbased_uses_name_from_packet_only; /* experimental */
	char   *hostbased_key_types;	/* Key types allowed for hostbased */
	char   *hostkeyalgorithms;	/* SSH2 server key types */
	char   *ca_sign_algorithms;	/* Allowed CA signature algorithms */
	int     pubkey_authentication;	/* If true, permit ssh2 pubkey authentication. */
	char   *pubkey_key_types;	/* Key types allowed for public key */
	int	pubkey_auth_options;	/* -1 or mask of PUBKEYAUTH_* flags */
	int     kerberos_authentication;	/* If true, permit Kerberos
						 * authentication. */
	int     kerberos_or_local_passwd;	/* If true, permit kerberos
						 * and any other password
						 * authentication mechanism,
						 * such as SecurID or
						 * /etc/passwd */
	int     kerberos_ticket_cleanup;	/* If true, destroy ticket
						 * file on logout. */
	int     kerberos_get_afs_token;		/* If true, try to get AFS token if
						 * authenticated with Kerberos. */
	int     gss_authentication;	/* If true, permit GSSAPI authentication */
	int     gss_cleanup_creds;	/* If true, destroy cred cache on logout */
	int     gss_strict_acceptor;	/* If true, restrict the GSSAPI acceptor name */
	int     password_authentication;	/* If true, permit password
						 * authentication. */
	int     kbd_interactive_authentication;	/* If true, permit */
	int     challenge_response_authentication;
	int     permit_empty_passwd;	/* If false, do not permit empty
					 * passwords. */
	int     permit_user_env;	/* If true, read ~/.ssh/environment */
	char   *permit_user_env_whitelist; /* pattern-list whitelist */
	int     compression;	/* If true, compression is allowed */
	int	allow_tcp_forwarding; /* One of FORWARD_* */
	int	allow_streamlocal_forwarding; /* One of FORWARD_* */
	int	allow_agent_forwarding;
	int	disable_forwarding;
	u_int num_allow_users;
	char   **allow_users;
	u_int num_deny_users;
	char   **deny_users;
	u_int num_allow_groups;
	char   **allow_groups;
	u_int num_deny_groups;
	char   **deny_groups;

	u_int num_subsystems;
	char   *subsystem_name[MAX_SUBSYSTEMS];
	char   *subsystem_command[MAX_SUBSYSTEMS];
	char   *subsystem_args[MAX_SUBSYSTEMS];

	u_int num_accept_env;
	char   **accept_env;
	u_int num_setenv;
	char   **setenv;

	int	max_startups_begin;
	int	max_startups_rate;
	int	max_startups;
	int	max_authtries;
	int	max_sessions;
	char   *banner;			/* SSH-2 banner message */
	int	use_dns;
	int	client_alive_interval;	/*
					 * poke the client this often to
					 * see if it's still there
					 */
	int	client_alive_count_max;	/*
					 * If the client is unresponsive
					 * for this many intervals above,
					 * disconnect the session
					 */

	u_int	num_authkeys_files;	/* Files containing public keys */
	char   **authorized_keys_files;

	char   *adm_forced_command;

	int	use_pam;		/* Enable auth via PAM */

	int	permit_tun;

	char   **permitted_opens;	/* May also be one of PERMITOPEN_* */
	u_int   num_permitted_opens;
	char   **permitted_listens; /* May also be one of PERMITOPEN_* */
	u_int   num_permitted_listens;

	char   *chroot_directory;
	char   *revoked_keys_file;
	char   *trusted_user_ca_keys;
	char   *authorized_keys_command;
	char   *authorized_keys_command_user;
	char   *authorized_principals_file;
	char   *authorized_principals_command;
	char   *authorized_principals_command_user;

	int64_t rekey_limit;
	int	rekey_interval;

	char   *version_addendum;	/* Appended to SSH banner */

	u_int	num_auth_methods;
	char   **auth_methods;

	int	fingerprint_hash;
	int	expose_userauth_info;
	u_int64_t timing_secret;
	char   *sk_provider;
}       ServerOptions;

/* From dispatch.h */
#define DISPATCH_MAX	255

enum {
	DISPATCH_BLOCK,
	DISPATCH_NONBLOCK
};

struct ssh;

typedef int dispatch_fn(int, u_int32_t, struct ssh *);
/* !dispatch.h */

/* From packet.h */
#include "sys-queue.h"

struct key_entry {
	TAILQ_ENTRY(key_entry) next;
	struct sshkey *key;
};

struct ssh {
	/* Session state */
	struct session_state *state;

	/* Key exchange */
	struct kex *kex;

	/* cached local and remote ip addresses and ports */
	char *remote_ipaddr;
	int remote_port;
	char *local_ipaddr;
	int local_port;
	char *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	char *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	int dispatch_skip_packets;

	/* datafellows */
	int compat;

	/* Lists for private and public keys */
	TAILQ_HEAD(, key_entry) private_keys;
	TAILQ_HEAD(, key_entry) public_keys;

	/* Client/Server authentication context */
	void *authctxt;

	/* Channels context */
	struct ssh_channels *chanctxt;

	/* APP data */
	void *app_data;
};
/* !packet.h */

/* From defines.h */
typedef int sig_atomic_t;
/* !defines.h */

/* From auth.h */

struct Authctxt {
	sig_atomic_t	 success;
	int		 authenticated;	/* authenticated and alarms cancelled */
	int		 postponed;	/* authentication needs another step */
	int		 valid;		/* user exists and is allowed to login */
	int		 attempt;
	int		 failures;
	int		 server_caused_failure;
	int		 force_pwchange;
	char		*user;		/* username sent by the client */
	char		*service;
	struct passwd	*pw;		/* set if 'valid' */
	char		*style;

	/* Method lists for multiple authentication */
	char		**auth_methods;	/* modified from server config */
	u_int		 num_auth_methods;

	/* Authentication method-specific data */
	void		*methoddata;
	void		*kbdintctxt;
#ifdef BSD_AUTH
	auth_session_t	*as;
#endif
#ifdef KRB5
	krb5_context	 krb5_ctx;
	krb5_ccache	 krb5_fwd_ccache;
	krb5_principal	 krb5_user;
	char		*krb5_ticket_file;
	char		*krb5_ccname;
#endif
	struct sshbuf	*loginmsg;

	/* Authentication keys already used; these will be refused henceforth */
	struct sshkey	**prev_keys;
	u_int		 nprev_keys;

	/* Last used key and ancillary information from active auth method */
	struct sshkey	*auth_method_key;
	char		*auth_method_info;

	/* Information exposed to session */
	struct sshbuf	*session_info;	/* Auth info for environment */
};
/* !auth.h */

/* From kex.h */
enum kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};
/* !kex.h */

/* From auth.c */

#define PACKET_MAX_SIZE (256 * 1024)

struct packet_state {
	u_int32_t seqnr;
	u_int32_t packets;
	u_int64_t blocks;
	u_int64_t bytes;
};

struct packet {
	TAILQ_ENTRY(packet) next;
	u_char type;
	struct sshbuf *payload;
};

typedef int (ssh_packet_hook_fn)(struct ssh *, struct sshbuf *,
    u_char *, void *);
struct session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	int connection_in;
	int connection_out;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	struct sshcipher_ctx *receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	struct sshcipher_ctx *send_context;

	/* Buffer for raw input data from the socket. */
	struct sshbuf *input;

	/* Buffer for raw output data going to the socket. */
	struct sshbuf *output;

	/* Buffer for the partial outgoing packet being constructed. */
	struct sshbuf *outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	struct sshbuf *incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	struct sshbuf *compression_buffer;

#ifdef WITH_ZLIB
	/* Incoming/outgoing compression dictionaries */
	z_stream compression_in_stream;
	z_stream compression_out_stream;
#endif
	int compression_in_started;
	int compression_out_started;
	int compression_in_failures;
	int compression_out_failures;

	/* default maximum packet size */
	u_int max_packet_size;

	/* Flag indicating whether this module has been initialized. */
	int initialized;

	/* Set to true if the connection is interactive. */
	int interactive_mode;

	/* Set to true if we are the server side. */
	int server_side;

	/* Set to true if we are authenticated. */
	int after_authentication;

	int keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	int packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	struct newkeys *newkeys[MODE_MAX];
	struct packet_state p_read, p_send;

	/* Volume-based rekeying */
	u_int64_t max_blocks_in, max_blocks_out, rekey_limit;

	/* Time-based rekeying */
	u_int32_t rekey_interval;	/* how often in seconds */
	time_t rekey_time;	/* time of last rekeying */

	/* roundup current message to extra_pad bytes */
	u_char extra_pad;

	/* XXX discard incoming data after MAC error */
	u_int packet_discard;
	size_t packet_discard_mac_already;
	struct sshmac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	int rekeying;

	/* Used in ssh_packet_send_mux() */
	int mux;

	/* Used in packet_set_interactive */
	int set_interactive_called;

	/* Used in packet_set_maxsize */
	int set_maxsize_called;

	/* One-off warning about weak ciphers */
	int cipher_warning_done;

	/* Hook for fuzzing inbound packets */
	ssh_packet_hook_fn *hook_in;
	void *hook_in_ctx;

	TAILQ_HEAD(, packet) outgoing;
};
/* !auth.c */

#endif /* !SSHD_H */
