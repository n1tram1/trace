#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define __AUTHKEYSCOMMAND__ "ssh-auth.sh"

#define USERNAME_MAX 64
#define ARGV_MAX 2

/*
 * Diagram below shows the flow of the specific sshd thread being traced.
 *
 *                             execve   execute authkeys prog
 *                                |        comm != "sshd"
 *                                v      (subprocess)              if auth fails +--------------------------------X  +-------------->exit_group(255)
 * recv connection            |                                |  |
 *  comm == "sshd"            |                                |  |
 * (connection process)  clone|                           wait4|  |
 *        |                   |                                |  |
 *        +-------------------+--------------------------------+--+--|--------|>start ssh session in same thread
 *                                                                   |alarm(0)|
 *
 * For some reason, the authkeys prog is executed twice.
 */

struct connection_process {
	char username[USERNAME_MAX];

	u64 pid_tgid;
	u32 subprocess_tgid;

	u64 subprocess_start_time;
	u64 subprocess_end_time;

	bool subprocess_execved;
};

BPF_HASH(processes, u64, struct connection_process);

struct authentication {
	char username[USERNAME_MAX];
	int success;
};

BPF_PERF_OUTPUT(authentication_events);

struct authorizedkeys_command {
	char username[USERNAME_MAX];
	u64 start;
	u64 end;
};

BPF_PERF_OUTPUT(authorizedkeyscommand_events);

static u64 get_pid_tgid(const struct task_struct *task)
{
	return ((u64)task->tgid << 32) | task->pid;
}

static u64 get_parent_pid_tgid(void)
{
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent;

	if (!cur)
		return 0;

	parent = cur->parent;
	if (!parent)
		return 0;

	return get_pid_tgid(parent);
}

static int is_comm_sshd(const struct task_struct *task)
{
	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(&comm, sizeof(comm));

	return strncmp(comm, "sshd", 4) == 0;
}

static int is_parent_comm_sshd(void)
{
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent;

	if (!cur)
		return 0;

	parent = cur->parent;
	if (!parent)
		return 0;

	return is_comm_sshd(parent);
}

static int is_current_comm_sshd(void)
{
	char comm[TASK_COMM_LEN];

	bpf_get_current_comm(&comm, sizeof(comm));

	return strncmp(comm, "sshd", 4) == 0;
}

static u32 get_current_pid()
{
	return (u32)bpf_get_current_pid_tgid();
}

/**
 * Detect the first clone, for the authkeys prog subprocess.
 *
 * Probe is hit when the connection thread uses clone (fork actually)
 * to launch a subprocess (the AuthorizedKeysCommand).
 */
TRACEPOINT_PROBE(syscalls, sys_exit_clone)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 child_tgid = args->ret;
	struct connection_process cur = {};

	if (!is_current_comm_sshd())
		return 1;

	/* Check we are in the parent */
	if (child_tgid == 0)
		return 1;

	cur.username[0] = '\0';
	cur.pid_tgid = pid_tgid;
	cur.subprocess_tgid = child_tgid;
	cur.subprocess_start_time = bpf_ktime_get_ns();
	cur.subprocess_execved = false;

	processes.update(&pid_tgid, &cur);

	return 0;
}

static bool is_authorizedkeys_command()
{
	char authkey_program[] = __AUTHKEYSCOMMAND__;
	char comm[sizeof(authkey_program)] = "";

	bpf_get_current_comm(&comm, sizeof(comm));

	/* Do the string comparison here to make the BPF checker happy. */
	for (size_t i = 0; i < sizeof(comm); i++) {
		if (comm[i] != authkey_program[i])
			return false;
	}

	return true;
}

static void get_argv(char **dst, const char *const *argv, size_t len)
{
	bpf_probe_read(dst, sizeof(*dst) * len, argv);
}

/**
 * Catch the subprocess just before it uses execve, to get its argv.
 * In the argv there can be the username with which the AuthorizedKeysCommand
 * is called.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
	u64 parent_pid_tgid = get_parent_pid_tgid();
	struct connection_process *parent;
	char *argv[ARGV_MAX];

	if ((parent = processes.lookup(&parent_pid_tgid)) == NULL)
		return 1;

	if (!is_parent_comm_sshd())
		return 1;

	get_argv(argv, args->argv, ARGV_MAX);

	bpf_probe_read(&parent->username, sizeof(parent->username), argv[1]);

	return 0;
}

/**
 * Catch when the execve syscall finishes in the subprocess.
 * We must check the new comm of the subprocess.
 * Be careful, sshd can call execve for other things.
 *
 * Catch when the subprocess has called exceve.
 */
TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
	u64 parent_pid_tgid = get_parent_pid_tgid();
	struct connection_process *parent;

	if ((parent = processes.lookup(&parent_pid_tgid)) == NULL)
		return 1;

	if (!is_authorizedkeys_command())
		return 1;

	parent->subprocess_execved = true;

	return 0;
}

static void copy_username(char *dst, const char *src)
{
	for (size_t i = 0; i < USERNAME_MAX; i++) {
		dst[i] = src[i];
	}
}

/**
 * Catch when the parent waits for its subprocess.
 * Check that the subprocess has execved to make sure
 * it is our child which has executed the AuthorizedKeysCommand.
 */
TRACEPOINT_PROBE(syscalls, sys_exit_wait4)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 waited_tgid = args->ret;
	struct connection_process *cur;

	if (!is_current_comm_sshd())
		return 1;

	if ((cur = processes.lookup(&pid_tgid)) == NULL)
		return 1;

	/* TODO: we should check the [int *options]
	 * to make sure the subprocess is dead.
	 */
	if (cur->subprocess_execved && waited_tgid == cur->subprocess_tgid) {
		cur->subprocess_end_time = bpf_ktime_get_ns();

		struct authorizedkeys_command cmd = {
			.start = cur->subprocess_start_time,
			.end = cur->subprocess_end_time,
		};
		copy_username(cmd.username, cur->username);

		authorizedkeyscommand_events.perf_submit(args, &cmd,
							 sizeof(cmd));
	}

	return 0;
}

/**
 * Catch all exit_group calls because we know that sshd will kill its thread
 * with an exit(255) if a failure occurs.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_exit_group)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connection_process *cur;

	if (!is_current_comm_sshd())
		return 1;

	if ((cur = processes.lookup(&pid_tgid)) == NULL)
		return 1;

	if (cur->subprocess_execved && args->error_code == 255) {
		struct authentication auth = {
			.success = false,
		};
		copy_username(auth.username, cur->username);

		authentication_events.perf_submit(args, &auth, sizeof(auth));

		processes.delete(&pid_tgid);
	}

	return 0;
}

/**
 * Before starting the auth sshd had set an alarm.
 * It disables that alarm once auth is successful.
 * Therefore if we catch an alarm(0), then the auth succeeded.
 * (We also check that the authkeys prog has ran)
 *
 * Catch when auth finishes successfully.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_alarm)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct connection_process *cur;

	if (!is_current_comm_sshd())
		return 1;

	if ((cur = processes.lookup(&pid_tgid)) == NULL)
		return 1;

	if (cur->subprocess_execved && args->seconds == 0) {
		struct authentication auth = {
			.success = true,
		};
		copy_username(auth.username, cur->username);

		authentication_events.perf_submit(args, &auth, sizeof(auth));

		processes.delete(&pid_tgid);
	}

	return 0;
}
