#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>

struct id {
	u32 src_addr;
	u32 dst_addr;
	u16 sport;
	u16 dport;
};

struct sshd_listener {
	u64 pid_tgid;

	struct socket *last_accepted;
	struct id last_id;
};

BPF_ARRAY(g_sshd_listener, struct sshd_listener, 1);

static struct sshd_listener *get_sshd_listener()
{
	int key = 0;
	struct sshd_listener *listener = g_sshd_listener.lookup(&key);

	return listener;
}

struct connection {
	u32 priv_tgid;
	u32 net_tgid;

	u64 sent;
	u64 received;

	struct id id;

	int auth_succesful;
	u64 start;
	u64 end;
};

BPF_HASH(connections, u32, struct connection);

BPF_PERF_OUTPUT(connection_events);

#define FILENAME_MAX 255

struct command {
	char filename[FILENAME_MAX];
	u64 start;
	u64 end;

	u32 parent_tgid;
	u32 current_tgid;

	struct id id;
};

BPF_HASH(commands, u32, struct command);

BPF_PERF_OUTPUT(command_events);

static int is_current_comm_sshd(void)
{
	char comm[TASK_COMM_LEN];

	bpf_get_current_comm(&comm, sizeof(comm));

	return strncmp(comm, "sshd", 4) == 0;
}

static u64 get_parent_pid_tgid(void)
{
	struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = curr->parent;

	if (!parent)
		return 0;

	return ((u64)parent->tgid << 32) | parent->pid;
}

static struct connection *get_ancestor_conn(void)
{
	struct task_struct *tsk = (struct task_struct *)bpf_get_current_task();
	struct connection *conn;

	for (int i = 0; i < 10 && tsk; i++)
	{
		u32 tgid = tsk->tgid;
		if ((conn = connections.lookup(&tgid)) != NULL)
			return conn;
		tsk = tsk->parent;
	}

	return NULL;
}


TRACEPOINT_PROBE(syscalls, sys_exit_accept)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sshd_listener *listener;

	if (!is_current_comm_sshd())
		return 1;

	if ((listener = get_sshd_listener()) == NULL)
		return 1;

	listener->pid_tgid = pid_tgid;
	listener->last_accepted = NULL;

	return 0;
}

int kprobe__inet_accept(struct pt_regs *ctx, struct socket *sock, struct socket *newsock, int flags,
		bool kern)
{
	struct sshd_listener *listener;

	if (!is_current_comm_sshd())
		return 1;

	if ((listener = get_sshd_listener()) == NULL)
		return 1;

	listener->last_accepted = newsock;

	return 0;
}

static void init_id(struct id *id, struct socket *socket)
{
	id->src_addr = socket->sk->sk_rcv_saddr;
	id->dst_addr = socket->sk->sk_daddr;
	id->sport = socket->sk->sk_num;
	id->dport = socket->sk->sk_dport;
}

int kretprobe__inet_accept(struct pt_regs *ctx)
{
	struct sshd_listener *listener;

	if (!is_current_comm_sshd())
		return 1;

	if ((listener = get_sshd_listener()) == NULL)
		return 1;

	init_id(&listener->last_id, listener->last_accepted);

	return 0;
}

static bool is_new_connection_clone(void)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sshd_listener *listener;

	if ((listener = get_sshd_listener()) == NULL)
		return false;

	return pid_tgid == listener->pid_tgid;
}

static void handle_new_connection(u32 conn_tgid)
{
	struct sshd_listener *listener;
	struct connection conn = {};

	if ((listener = get_sshd_listener()) == NULL)
		return;

	conn.priv_tgid = conn_tgid;
	conn.net_tgid = 0;
	conn.sent = 0;
	conn.received = 0;
	conn.id = listener->last_id;
	conn.auth_succesful = 0;
	conn.start = bpf_ktime_get_ns();
	conn.end = 0;

	connections.insert(&conn_tgid, &conn);

	bpf_trace_printk("conn_tgid %u\n", conn_tgid);
}

static bool is_new_net_clone(void)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	struct connection *conn;

	if ((conn = connections.lookup(&tgid)) == NULL)
		return false;

	return tgid == conn->priv_tgid;
}

static void handle_new_net_clone(u32 net_tgid)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connection *conn;

	if ((conn = get_ancestor_conn()) == NULL)
		return;

	conn->net_tgid = net_tgid;
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sshd_listener *listener;
	u32 child_tgid = args->ret;
	struct connection conn = {};

	if ((listener = get_sshd_listener()) == NULL)
		return 1;

	if (is_new_connection_clone()) {
		handle_new_connection(child_tgid);
		return 0;
	}

	if (is_new_net_clone()) {
		handle_new_net_clone(child_tgid);
		return 0;
	}

	return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
	u32 parent_tgid = get_parent_pid_tgid() >> 32;
	u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
	struct connection *conn;
	struct command cmd = {};

	if ((conn = get_ancestor_conn()) == NULL)
		return 1;

	cmd.filename[0] = '\0';
	cmd.start = bpf_ktime_get_ns();
	cmd.end = 0;
	cmd.parent_tgid = parent_tgid;
	cmd.current_tgid = current_tgid;
	cmd.id = conn->id;
	bpf_probe_read_str(&cmd.filename, sizeof(cmd.filename), args->filename);

	commands.insert(&current_tgid, &cmd);

	return 0;
}

int kprobe__do_exit(struct pt_regs *ctx, int code)
{
	u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
	struct command *cmd;
	struct connection *conn;

	if ((conn = connections.lookup(&current_tgid)) != NULL) {
		conn->end = bpf_ktime_get_ns();

		connection_events.perf_submit(ctx, conn, sizeof(*conn));

		connections.delete(&current_tgid);

		return 0;
	}

	if ((cmd = commands.lookup(&current_tgid)) != NULL) {
		cmd->end = bpf_ktime_get_ns();
		command_events.perf_submit(ctx, cmd, sizeof(*cmd));

		return 0;
	}


	return 1;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
	u32 parent_tgid = get_parent_pid_tgid() >> 32;
	struct connection *conn;

	if ((conn = connections.lookup(&parent_tgid)) == NULL)
		return 1;

	conn->sent += size;

	return 0;
}

int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
	u32 parent_tgid = get_parent_pid_tgid() >> 32;
	struct connection *conn;

	if ((conn = connections.lookup(&parent_tgid)) == NULL)
		return 1;

	conn->received += size;

	return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_alarm)
{
	u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
	struct connection *conn;

	if ((conn = connections.lookup(&current_tgid)) == NULL)
		return 1;
	bpf_trace_printk("go alarm %d\n", args->seconds);

	if (args->seconds == 0)
		conn->auth_succesful = 1;

	return 0;

}
