	laid_sc_table[__NR_io_destroy] = (void *)sys_call_table[__NR_io_destroy];
	sys_call_table[__NR_io_destroy] = (unsigned long *)susp_sys_io_destroy;

	laid_sc_table[__NR_io_cancel] = (void *)sys_call_table[__NR_io_cancel];
	sys_call_table[__NR_io_cancel] = (unsigned long *)susp_sys_io_cancel;

	laid_sc_table[__NR_listxattr] = (void *)sys_call_table[__NR_listxattr];
	sys_call_table[__NR_listxattr] = (unsigned long *)susp_sys_listxattr;

	laid_sc_table[__NR_llistxattr] = (void *)sys_call_table[__NR_llistxattr];
	sys_call_table[__NR_llistxattr] = (unsigned long *)susp_sys_llistxattr;

	laid_sc_table[__NR_flistxattr] = (void *)sys_call_table[__NR_flistxattr];
	sys_call_table[__NR_flistxattr] = (unsigned long *)susp_sys_flistxattr;

	laid_sc_table[__NR_removexattr] = (void *)sys_call_table[__NR_removexattr];
	sys_call_table[__NR_removexattr] = (unsigned long *)susp_sys_removexattr;

	laid_sc_table[__NR_lremovexattr] = (void *)sys_call_table[__NR_lremovexattr];
	sys_call_table[__NR_lremovexattr] = (unsigned long *)susp_sys_lremovexattr;

	laid_sc_table[__NR_fremovexattr] = (void *)sys_call_table[__NR_fremovexattr];
	sys_call_table[__NR_fremovexattr] = (unsigned long *)susp_sys_fremovexattr;

	laid_sc_table[__NR_getcwd] = (void *)sys_call_table[__NR_getcwd];
	sys_call_table[__NR_getcwd] = (unsigned long *)susp_sys_getcwd;

	laid_sc_table[__NR_eventfd2] = (void *)sys_call_table[__NR_eventfd2];
	sys_call_table[__NR_eventfd2] = (unsigned long *)susp_sys_eventfd2;

	laid_sc_table[__NR_epoll_create1] = (void *)sys_call_table[__NR_epoll_create1];
	sys_call_table[__NR_epoll_create1] = (unsigned long *)susp_sys_epoll_create1;

	laid_sc_table[__NR_epoll_ctl] = (void *)sys_call_table[__NR_epoll_ctl];
	sys_call_table[__NR_epoll_ctl] = (unsigned long *)susp_sys_epoll_ctl;

	laid_sc_table[__NR_dup] = (void *)sys_call_table[__NR_dup];
	sys_call_table[__NR_dup] = (unsigned long *)susp_sys_dup;

	laid_sc_table[__NR_dup3] = (void *)sys_call_table[__NR_dup3];
	sys_call_table[__NR_dup3] = (unsigned long *)susp_sys_dup3;

	laid_sc_table[__NR_inotify_init1] = (void *)sys_call_table[__NR_inotify_init1];
	sys_call_table[__NR_inotify_init1] = (unsigned long *)susp_sys_inotify_init1;

	laid_sc_table[__NR_inotify_add_watch] = (void *)sys_call_table[__NR_inotify_add_watch];
	sys_call_table[__NR_inotify_add_watch] = (unsigned long *)susp_sys_inotify_add_watch;

	laid_sc_table[__NR_inotify_rm_watch] = (void *)sys_call_table[__NR_inotify_rm_watch];
	sys_call_table[__NR_inotify_rm_watch] = (unsigned long *)susp_sys_inotify_rm_watch;

	laid_sc_table[__NR_ioprio_set] = (void *)sys_call_table[__NR_ioprio_set];
	sys_call_table[__NR_ioprio_set] = (unsigned long *)susp_sys_ioprio_set;

	laid_sc_table[__NR_ioprio_get] = (void *)sys_call_table[__NR_ioprio_get];
	sys_call_table[__NR_ioprio_get] = (unsigned long *)susp_sys_ioprio_get;

	laid_sc_table[__NR_flock] = (void *)sys_call_table[__NR_flock];
	sys_call_table[__NR_flock] = (unsigned long *)susp_sys_flock;

	laid_sc_table[__NR_mknodat] = (void *)sys_call_table[__NR_mknodat];
	sys_call_table[__NR_mknodat] = (unsigned long *)susp_sys_mknodat;

	laid_sc_table[__NR_mkdirat] = (void *)sys_call_table[__NR_mkdirat];
	sys_call_table[__NR_mkdirat] = (unsigned long *)susp_sys_mkdirat;

	laid_sc_table[__NR_unlinkat] = (void *)sys_call_table[__NR_unlinkat];
	sys_call_table[__NR_unlinkat] = (unsigned long *)susp_sys_unlinkat;

	laid_sc_table[__NR_symlinkat] = (void *)sys_call_table[__NR_symlinkat];
	sys_call_table[__NR_symlinkat] = (unsigned long *)susp_sys_symlinkat;

	laid_sc_table[__NR_linkat] = (void *)sys_call_table[__NR_linkat];
	sys_call_table[__NR_linkat] = (unsigned long *)susp_sys_linkat;

	laid_sc_table[__NR_renameat] = (void *)sys_call_table[__NR_renameat];
	sys_call_table[__NR_renameat] = (unsigned long *)susp_sys_renameat;

	laid_sc_table[__NR_pivot_root] = (void *)sys_call_table[__NR_pivot_root];
	sys_call_table[__NR_pivot_root] = (unsigned long *)susp_sys_pivot_root;

	laid_sc_table[__NR_faccessat] = (void *)sys_call_table[__NR_faccessat];
	sys_call_table[__NR_faccessat] = (unsigned long *)susp_sys_faccessat;

	laid_sc_table[__NR_chdir] = (void *)sys_call_table[__NR_chdir];
	sys_call_table[__NR_chdir] = (unsigned long *)susp_sys_chdir;

	laid_sc_table[__NR_fchdir] = (void *)sys_call_table[__NR_fchdir];
	sys_call_table[__NR_fchdir] = (unsigned long *)susp_sys_fchdir;

	laid_sc_table[__NR_chroot] = (void *)sys_call_table[__NR_chroot];
	sys_call_table[__NR_chroot] = (unsigned long *)susp_sys_chroot;

	laid_sc_table[__NR_fchmod] = (void *)sys_call_table[__NR_fchmod];
	sys_call_table[__NR_fchmod] = (unsigned long *)susp_sys_fchmod;

	laid_sc_table[__NR_fchmodat] = (void *)sys_call_table[__NR_fchmodat];
	sys_call_table[__NR_fchmodat] = (unsigned long *)susp_sys_fchmodat;

	laid_sc_table[__NR_fchownat] = (void *)sys_call_table[__NR_fchownat];
	sys_call_table[__NR_fchownat] = (unsigned long *)susp_sys_fchownat;

	laid_sc_table[__NR_fchown] = (void *)sys_call_table[__NR_fchown];
	sys_call_table[__NR_fchown] = (unsigned long *)susp_sys_fchown;

	laid_sc_table[__NR_close] = (void *)sys_call_table[__NR_close];
	sys_call_table[__NR_close] = (unsigned long *)susp_sys_close;

	laid_sc_table[__NR_pipe2] = (void *)sys_call_table[__NR_pipe2];
	sys_call_table[__NR_pipe2] = (unsigned long *)susp_sys_pipe2;

	laid_sc_table[__NR_read] = (void *)sys_call_table[__NR_read];
	sys_call_table[__NR_read] = (unsigned long *)susp_sys_read;

	laid_sc_table[__NR_write] = (void *)sys_call_table[__NR_write];
	sys_call_table[__NR_write] = (unsigned long *)susp_sys_write;

	laid_sc_table[__NR_splice] = (void *)sys_call_table[__NR_splice];
	sys_call_table[__NR_splice] = (unsigned long *)susp_sys_splice;

	laid_sc_table[__NR_tee] = (void *)sys_call_table[__NR_tee];
	sys_call_table[__NR_tee] = (unsigned long *)susp_sys_tee;

	laid_sc_table[__NR_readlinkat] = (void *)sys_call_table[__NR_readlinkat];
	sys_call_table[__NR_readlinkat] = (unsigned long *)susp_sys_readlinkat;

	laid_sc_table[__NR_fsync] = (void *)sys_call_table[__NR_fsync];
	sys_call_table[__NR_fsync] = (unsigned long *)susp_sys_fsync;

	laid_sc_table[__NR_fdatasync] = (void *)sys_call_table[__NR_fdatasync];
	sys_call_table[__NR_fdatasync] = (unsigned long *)susp_sys_fdatasync;

	laid_sc_table[__NR_timerfd_create] = (void *)sys_call_table[__NR_timerfd_create];
	sys_call_table[__NR_timerfd_create] = (unsigned long *)susp_sys_timerfd_create;

	laid_sc_table[__NR_acct] = (void *)sys_call_table[__NR_acct];
	sys_call_table[__NR_acct] = (unsigned long *)susp_sys_acct;

	laid_sc_table[__NR_capget] = (void *)sys_call_table[__NR_capget];
	sys_call_table[__NR_capget] = (unsigned long *)susp_sys_capget;

	laid_sc_table[__NR_capset] = (void *)sys_call_table[__NR_capset];
	sys_call_table[__NR_capset] = (unsigned long *)susp_sys_capset;

	laid_sc_table[__NR_personality] = (void *)sys_call_table[__NR_personality];
	sys_call_table[__NR_personality] = (unsigned long *)susp_sys_personality;

	laid_sc_table[__NR_exit] = (void *)sys_call_table[__NR_exit];
	sys_call_table[__NR_exit] = (unsigned long *)susp_sys_exit;

	laid_sc_table[__NR_exit_group] = (void *)sys_call_table[__NR_exit_group];
	sys_call_table[__NR_exit_group] = (unsigned long *)susp_sys_exit_group;

	laid_sc_table[__NR_set_tid_address] = (void *)sys_call_table[__NR_set_tid_address];
	sys_call_table[__NR_set_tid_address] = (unsigned long *)susp_sys_set_tid_address;

	laid_sc_table[__NR_unshare] = (void *)sys_call_table[__NR_unshare];
	sys_call_table[__NR_unshare] = (unsigned long *)susp_sys_unshare;

	laid_sc_table[__NR_delete_module] = (void *)sys_call_table[__NR_delete_module];
	sys_call_table[__NR_delete_module] = (unsigned long *)susp_sys_delete_module;

	laid_sc_table[__NR_timer_getoverrun] = (void *)sys_call_table[__NR_timer_getoverrun];
	sys_call_table[__NR_timer_getoverrun] = (unsigned long *)susp_sys_timer_getoverrun;

	laid_sc_table[__NR_timer_delete] = (void *)sys_call_table[__NR_timer_delete];
	sys_call_table[__NR_timer_delete] = (unsigned long *)susp_sys_timer_delete;

	laid_sc_table[__NR_syslog] = (void *)sys_call_table[__NR_syslog];
	sys_call_table[__NR_syslog] = (unsigned long *)susp_sys_syslog;

	laid_sc_table[__NR_ptrace] = (void *)sys_call_table[__NR_ptrace];
	sys_call_table[__NR_ptrace] = (unsigned long *)susp_sys_ptrace;

	laid_sc_table[__NR_sched_setparam] = (void *)sys_call_table[__NR_sched_setparam];
	sys_call_table[__NR_sched_setparam] = (unsigned long *)susp_sys_sched_setparam;

	laid_sc_table[__NR_sched_setscheduler] = (void *)sys_call_table[__NR_sched_setscheduler];
	sys_call_table[__NR_sched_setscheduler] = (unsigned long *)susp_sys_sched_setscheduler;

	laid_sc_table[__NR_sched_getscheduler] = (void *)sys_call_table[__NR_sched_getscheduler];
	sys_call_table[__NR_sched_getscheduler] = (unsigned long *)susp_sys_sched_getscheduler;

	laid_sc_table[__NR_sched_getparam] = (void *)sys_call_table[__NR_sched_getparam];
	sys_call_table[__NR_sched_getparam] = (unsigned long *)susp_sys_sched_getparam;

	laid_sc_table[__NR_sched_get_priority_max] = (void *)sys_call_table[__NR_sched_get_priority_max];
	sys_call_table[__NR_sched_get_priority_max] = (unsigned long *)susp_sys_sched_get_priority_max;

	laid_sc_table[__NR_sched_get_priority_min] = (void *)sys_call_table[__NR_sched_get_priority_min];
	sys_call_table[__NR_sched_get_priority_min] = (unsigned long *)susp_sys_sched_get_priority_min;

	laid_sc_table[__NR_kill] = (void *)sys_call_table[__NR_kill];
	sys_call_table[__NR_kill] = (unsigned long *)susp_sys_kill;

	laid_sc_table[__NR_tkill] = (void *)sys_call_table[__NR_tkill];
	sys_call_table[__NR_tkill] = (unsigned long *)susp_sys_tkill;

	laid_sc_table[__NR_tgkill] = (void *)sys_call_table[__NR_tgkill];
	sys_call_table[__NR_tgkill] = (unsigned long *)susp_sys_tgkill;

	laid_sc_table[__NR_setpriority] = (void *)sys_call_table[__NR_setpriority];
	sys_call_table[__NR_setpriority] = (unsigned long *)susp_sys_setpriority;

	laid_sc_table[__NR_getpriority] = (void *)sys_call_table[__NR_getpriority];
	sys_call_table[__NR_getpriority] = (unsigned long *)susp_sys_getpriority;

	laid_sc_table[__NR_setregid] = (void *)sys_call_table[__NR_setregid];
	sys_call_table[__NR_setregid] = (unsigned long *)susp_sys_setregid;

	laid_sc_table[__NR_setgid] = (void *)sys_call_table[__NR_setgid];
	sys_call_table[__NR_setgid] = (unsigned long *)susp_sys_setgid;

	laid_sc_table[__NR_setreuid] = (void *)sys_call_table[__NR_setreuid];
	sys_call_table[__NR_setreuid] = (unsigned long *)susp_sys_setreuid;

	laid_sc_table[__NR_setuid] = (void *)sys_call_table[__NR_setuid];
	sys_call_table[__NR_setuid] = (unsigned long *)susp_sys_setuid;

	laid_sc_table[__NR_setresuid] = (void *)sys_call_table[__NR_setresuid];
	sys_call_table[__NR_setresuid] = (unsigned long *)susp_sys_setresuid;

	laid_sc_table[__NR_getresuid] = (void *)sys_call_table[__NR_getresuid];
	sys_call_table[__NR_getresuid] = (unsigned long *)susp_sys_getresuid;

	laid_sc_table[__NR_setresgid] = (void *)sys_call_table[__NR_setresgid];
	sys_call_table[__NR_setresgid] = (unsigned long *)susp_sys_setresgid;

	laid_sc_table[__NR_getresgid] = (void *)sys_call_table[__NR_getresgid];
	sys_call_table[__NR_getresgid] = (unsigned long *)susp_sys_getresgid;

	laid_sc_table[__NR_setfsuid] = (void *)sys_call_table[__NR_setfsuid];
	sys_call_table[__NR_setfsuid] = (unsigned long *)susp_sys_setfsuid;

	laid_sc_table[__NR_setfsgid] = (void *)sys_call_table[__NR_setfsgid];
	sys_call_table[__NR_setfsgid] = (unsigned long *)susp_sys_setfsgid;

	laid_sc_table[__NR_setpgid] = (void *)sys_call_table[__NR_setpgid];
	sys_call_table[__NR_setpgid] = (unsigned long *)susp_sys_setpgid;

	laid_sc_table[__NR_getpgid] = (void *)sys_call_table[__NR_getpgid];
	sys_call_table[__NR_getpgid] = (unsigned long *)susp_sys_getpgid;

	laid_sc_table[__NR_getsid] = (void *)sys_call_table[__NR_getsid];
	sys_call_table[__NR_getsid] = (unsigned long *)susp_sys_getsid;

	laid_sc_table[__NR_getgroups] = (void *)sys_call_table[__NR_getgroups];
	sys_call_table[__NR_getgroups] = (unsigned long *)susp_sys_getgroups;

	laid_sc_table[__NR_setgroups] = (void *)sys_call_table[__NR_setgroups];
	sys_call_table[__NR_setgroups] = (unsigned long *)susp_sys_setgroups;

	laid_sc_table[__NR_sethostname] = (void *)sys_call_table[__NR_sethostname];
	sys_call_table[__NR_sethostname] = (unsigned long *)susp_sys_sethostname;

	laid_sc_table[__NR_setdomainname] = (void *)sys_call_table[__NR_setdomainname];
	sys_call_table[__NR_setdomainname] = (unsigned long *)susp_sys_setdomainname;

	laid_sc_table[__NR_umask] = (void *)sys_call_table[__NR_umask];
	sys_call_table[__NR_umask] = (unsigned long *)susp_sys_umask;

	laid_sc_table[__NR_prctl] = (void *)sys_call_table[__NR_prctl];
	sys_call_table[__NR_prctl] = (unsigned long *)susp_sys_prctl;

	laid_sc_table[__NR_getcpu] = (void *)sys_call_table[__NR_getcpu];
	sys_call_table[__NR_getcpu] = (unsigned long *)susp_sys_getcpu;

	laid_sc_table[__NR_mq_unlink] = (void *)sys_call_table[__NR_mq_unlink];
	sys_call_table[__NR_mq_unlink] = (unsigned long *)susp_sys_mq_unlink;

	laid_sc_table[__NR_msgget] = (void *)sys_call_table[__NR_msgget];
	sys_call_table[__NR_msgget] = (unsigned long *)susp_sys_msgget;

	laid_sc_table[__NR_semget] = (void *)sys_call_table[__NR_semget];
	sys_call_table[__NR_semget] = (unsigned long *)susp_sys_semget;

	laid_sc_table[__NR_semop] = (void *)sys_call_table[__NR_semop];
	sys_call_table[__NR_semop] = (unsigned long *)susp_sys_semop;

	laid_sc_table[__NR_shmget] = (void *)sys_call_table[__NR_shmget];
	sys_call_table[__NR_shmget] = (unsigned long *)susp_sys_shmget;

	laid_sc_table[__NR_shmdt] = (void *)sys_call_table[__NR_shmdt];
	sys_call_table[__NR_shmdt] = (unsigned long *)susp_sys_shmdt;

	laid_sc_table[__NR_brk] = (void *)sys_call_table[__NR_brk];
	sys_call_table[__NR_brk] = (unsigned long *)susp_sys_brk;

	laid_sc_table[__NR_munmap] = (void *)sys_call_table[__NR_munmap];
	sys_call_table[__NR_munmap] = (unsigned long *)susp_sys_munmap;

	laid_sc_table[__NR_mremap] = (void *)sys_call_table[__NR_mremap];
	sys_call_table[__NR_mremap] = (unsigned long *)susp_sys_mremap;

	laid_sc_table[__NR_request_key] = (void *)sys_call_table[__NR_request_key];
	sys_call_table[__NR_request_key] = (unsigned long *)susp_sys_request_key;

	laid_sc_table[__NR_swapon] = (void *)sys_call_table[__NR_swapon];
	sys_call_table[__NR_swapon] = (unsigned long *)susp_sys_swapon;

	laid_sc_table[__NR_swapoff] = (void *)sys_call_table[__NR_swapoff];
	sys_call_table[__NR_swapoff] = (unsigned long *)susp_sys_swapoff;

	laid_sc_table[__NR_mprotect] = (void *)sys_call_table[__NR_mprotect];
	sys_call_table[__NR_mprotect] = (unsigned long *)susp_sys_mprotect;

	laid_sc_table[__NR_msync] = (void *)sys_call_table[__NR_msync];
	sys_call_table[__NR_msync] = (unsigned long *)susp_sys_msync;

	laid_sc_table[__NR_mlock] = (void *)sys_call_table[__NR_mlock];
	sys_call_table[__NR_mlock] = (unsigned long *)susp_sys_mlock;

	laid_sc_table[__NR_munlock] = (void *)sys_call_table[__NR_munlock];
	sys_call_table[__NR_munlock] = (unsigned long *)susp_sys_munlock;

	laid_sc_table[__NR_mlockall] = (void *)sys_call_table[__NR_mlockall];
	sys_call_table[__NR_mlockall] = (unsigned long *)susp_sys_mlockall;

	laid_sc_table[__NR_mincore] = (void *)sys_call_table[__NR_mincore];
	sys_call_table[__NR_mincore] = (unsigned long *)susp_sys_mincore;

	laid_sc_table[__NR_madvise] = (void *)sys_call_table[__NR_madvise];
	sys_call_table[__NR_madvise] = (unsigned long *)susp_sys_madvise;

	laid_sc_table[__NR_remap_file_pages] = (void *)sys_call_table[__NR_remap_file_pages];
	sys_call_table[__NR_remap_file_pages] = (unsigned long *)susp_sys_remap_file_pages;

	laid_sc_table[__NR_perf_event_open] = (void *)sys_call_table[__NR_perf_event_open];
	sys_call_table[__NR_perf_event_open] = (unsigned long *)susp_sys_perf_event_open;

	laid_sc_table[__NR_prlimit64] = (void *)sys_call_table[__NR_prlimit64];
	sys_call_table[__NR_prlimit64] = (unsigned long *)susp_sys_prlimit64;

	laid_sc_table[__NR_fanotify_init] = (void *)sys_call_table[__NR_fanotify_init];
	sys_call_table[__NR_fanotify_init] = (unsigned long *)susp_sys_fanotify_init;

	laid_sc_table[__NR_fanotify_mark] = (void *)sys_call_table[__NR_fanotify_mark];
	sys_call_table[__NR_fanotify_mark] = (unsigned long *)susp_sys_fanotify_mark;

	laid_sc_table[__NR_name_to_handle_at] = (void *)sys_call_table[__NR_name_to_handle_at];
	sys_call_table[__NR_name_to_handle_at] = (unsigned long *)susp_sys_name_to_handle_at;

	laid_sc_table[__NR_syncfs] = (void *)sys_call_table[__NR_syncfs];
	sys_call_table[__NR_syncfs] = (unsigned long *)susp_sys_syncfs;

	laid_sc_table[__NR_setns] = (void *)sys_call_table[__NR_setns];
	sys_call_table[__NR_setns] = (unsigned long *)susp_sys_setns;

	laid_sc_table[__NR_kcmp] = (void *)sys_call_table[__NR_kcmp];
	sys_call_table[__NR_kcmp] = (unsigned long *)susp_sys_kcmp;

	laid_sc_table[__NR_finit_module] = (void *)sys_call_table[__NR_finit_module];
	sys_call_table[__NR_finit_module] = (unsigned long *)susp_sys_finit_module;

	laid_sc_table[__NR_open] = (void *)sys_call_table[__NR_open];
	sys_call_table[__NR_open] = (unsigned long *)susp_sys_open;

	laid_sc_table[__NR_link] = (void *)sys_call_table[__NR_link];
	sys_call_table[__NR_link] = (unsigned long *)susp_sys_link;

	laid_sc_table[__NR_unlink] = (void *)sys_call_table[__NR_unlink];
	sys_call_table[__NR_unlink] = (unsigned long *)susp_sys_unlink;

	laid_sc_table[__NR_mknod] = (void *)sys_call_table[__NR_mknod];
	sys_call_table[__NR_mknod] = (unsigned long *)susp_sys_mknod;

	laid_sc_table[__NR_chmod] = (void *)sys_call_table[__NR_chmod];
	sys_call_table[__NR_chmod] = (unsigned long *)susp_sys_chmod;

	laid_sc_table[__NR_chown] = (void *)sys_call_table[__NR_chown];
	sys_call_table[__NR_chown] = (unsigned long *)susp_sys_chown;

	laid_sc_table[__NR_mkdir] = (void *)sys_call_table[__NR_mkdir];
	sys_call_table[__NR_mkdir] = (unsigned long *)susp_sys_mkdir;

	laid_sc_table[__NR_rmdir] = (void *)sys_call_table[__NR_rmdir];
	sys_call_table[__NR_rmdir] = (unsigned long *)susp_sys_rmdir;

	laid_sc_table[__NR_lchown] = (void *)sys_call_table[__NR_lchown];
	sys_call_table[__NR_lchown] = (unsigned long *)susp_sys_lchown;

	laid_sc_table[__NR_access] = (void *)sys_call_table[__NR_access];
	sys_call_table[__NR_access] = (unsigned long *)susp_sys_access;

	laid_sc_table[__NR_rename] = (void *)sys_call_table[__NR_rename];
	sys_call_table[__NR_rename] = (unsigned long *)susp_sys_rename;

	laid_sc_table[__NR_readlink] = (void *)sys_call_table[__NR_readlink];
	sys_call_table[__NR_readlink] = (unsigned long *)susp_sys_readlink;

	laid_sc_table[__NR_symlink] = (void *)sys_call_table[__NR_symlink];
	sys_call_table[__NR_symlink] = (unsigned long *)susp_sys_symlink;

	laid_sc_table[__NR_utimes] = (void *)sys_call_table[__NR_utimes];
	sys_call_table[__NR_utimes] = (unsigned long *)susp_sys_utimes;

	laid_sc_table[__NR_pipe] = (void *)sys_call_table[__NR_pipe];
	sys_call_table[__NR_pipe] = (unsigned long *)susp_sys_pipe;

	laid_sc_table[__NR_dup2] = (void *)sys_call_table[__NR_dup2];
	sys_call_table[__NR_dup2] = (unsigned long *)susp_sys_dup2;

	laid_sc_table[__NR_epoll_create] = (void *)sys_call_table[__NR_epoll_create];
	sys_call_table[__NR_epoll_create] = (unsigned long *)susp_sys_epoll_create;

	laid_sc_table[__NR_eventfd] = (void *)sys_call_table[__NR_eventfd];
	sys_call_table[__NR_eventfd] = (unsigned long *)susp_sys_eventfd;

	laid_sc_table[__NR_signalfd] = (void *)sys_call_table[__NR_signalfd];
	sys_call_table[__NR_signalfd] = (unsigned long *)susp_sys_signalfd;

	laid_sc_table[__NR_sendfile] = (void *)sys_call_table[__NR_sendfile];
	sys_call_table[__NR_sendfile] = (unsigned long *)susp_sys_sendfile;

	laid_sc_table[__NR_ftruncate] = (void *)sys_call_table[__NR_ftruncate];
	sys_call_table[__NR_ftruncate] = (unsigned long *)susp_sys_ftruncate;

	laid_sc_table[__NR_truncate] = (void *)sys_call_table[__NR_truncate];
	sys_call_table[__NR_truncate] = (unsigned long *)susp_sys_truncate;

	laid_sc_table[__NR_fcntl] = (void *)sys_call_table[__NR_fcntl];
	sys_call_table[__NR_fcntl] = (unsigned long *)susp_sys_fcntl;

	laid_sc_table[__NR_fadvise64] = (void *)sys_call_table[__NR_fadvise64];
	sys_call_table[__NR_fadvise64] = (unsigned long *)susp_sys_fadvise64;

	laid_sc_table[__NR_newfstatat] = (void *)sys_call_table[__NR_newfstatat];
	sys_call_table[__NR_newfstatat] = (unsigned long *)susp_sys_newfstatat;

	laid_sc_table[__NR_fstatfs] = (void *)sys_call_table[__NR_fstatfs];
	sys_call_table[__NR_fstatfs] = (unsigned long *)susp_sys_fstatfs;

	laid_sc_table[__NR_statfs] = (void *)sys_call_table[__NR_statfs];
	sys_call_table[__NR_statfs] = (unsigned long *)susp_sys_statfs;

	laid_sc_table[__NR_lseek] = (void *)sys_call_table[__NR_lseek];
	sys_call_table[__NR_lseek] = (unsigned long *)susp_sys_lseek;

	laid_sc_table[__NR_alarm] = (void *)sys_call_table[__NR_alarm];
	sys_call_table[__NR_alarm] = (unsigned long *)susp_sys_alarm;

	laid_sc_table[__NR_time] = (void *)sys_call_table[__NR_time];
	sys_call_table[__NR_time] = (unsigned long *)susp_sys_time;

	laid_sc_table[__NR_utime] = (void *)sys_call_table[__NR_utime];
	sys_call_table[__NR_utime] = (unsigned long *)susp_sys_utime;

	laid_sc_table[__NR_creat] = (void *)sys_call_table[__NR_creat];
	sys_call_table[__NR_creat] = (unsigned long *)susp_sys_creat;

	laid_sc_table[__NR_getdents] = (void *)sys_call_table[__NR_getdents];
	sys_call_table[__NR_getdents] = (unsigned long *)susp_sys_getdents;

	laid_sc_table[__NR_futimesat] = (void *)sys_call_table[__NR_futimesat];
	sys_call_table[__NR_futimesat] = (unsigned long *)susp_sys_futimesat;

	laid_sc_table[__NR_select] = (void *)sys_call_table[__NR_select];
	sys_call_table[__NR_select] = (unsigned long *)susp_sys_select;

	laid_sc_table[__NR_poll] = (void *)sys_call_table[__NR_poll];
	sys_call_table[__NR_poll] = (unsigned long *)susp_sys_poll;

	laid_sc_table[__NR_epoll_wait] = (void *)sys_call_table[__NR_epoll_wait];
	sys_call_table[__NR_epoll_wait] = (unsigned long *)susp_sys_epoll_wait;

	laid_sc_table[__NR_ustat] = (void *)sys_call_table[__NR_ustat];
	sys_call_table[__NR_ustat] = (unsigned long *)susp_sys_ustat;

	laid_sc_table[__NR_uselib] = (void *)sys_call_table[__NR_uselib];
	sys_call_table[__NR_uselib] = (unsigned long *)susp_sys_uselib;
