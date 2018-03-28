int restore_sc_table(void *data) {
	SUSP_VERSA(io_destroy)
	SUSP_VERSA(io_cancel)
	SUSP_VERSA(listxattr)
	SUSP_VERSA(llistxattr)
	SUSP_VERSA(flistxattr)
	SUSP_VERSA(removexattr)
	SUSP_VERSA(lremovexattr)
	SUSP_VERSA(fremovexattr)
	SUSP_VERSA(getcwd)
	SUSP_VERSA(eventfd2)
	SUSP_VERSA(epoll_create1)
	SUSP_VERSA(epoll_ctl)
	SUSP_VERSA(dup)
	SUSP_VERSA(dup3)
	SUSP_VERSA(inotify_init1)
	SUSP_VERSA(inotify_add_watch)
	SUSP_VERSA(inotify_rm_watch)
	SUSP_VERSA(ioprio_set)
	SUSP_VERSA(ioprio_get)
	SUSP_VERSA(flock)
	SUSP_VERSA(mknodat)
	SUSP_VERSA(mkdirat)
	SUSP_VERSA(unlinkat)
	SUSP_VERSA(symlinkat)
	SUSP_VERSA(linkat)
	SUSP_VERSA(renameat)
	SUSP_VERSA(pivot_root)
	SUSP_VERSA(faccessat)
	SUSP_VERSA(chdir)
	SUSP_VERSA(fchdir)
	SUSP_VERSA(chroot)
	SUSP_VERSA(fchmod)
	SUSP_VERSA(fchmodat)
	SUSP_VERSA(fchownat)
	SUSP_VERSA(fchown)
	SUSP_VERSA(close)
	SUSP_VERSA(pipe2)
	SUSP_VERSA(read)
	SUSP_VERSA(write)
	SUSP_VERSA(splice)
	SUSP_VERSA(tee)
	SUSP_VERSA(readlinkat)
	SUSP_VERSA(fsync)
	SUSP_VERSA(fdatasync)
	SUSP_VERSA(timerfd_create)
	SUSP_VERSA(acct)
	SUSP_VERSA(capget)
	SUSP_VERSA(capset)
	SUSP_VERSA(personality)
	SUSP_VERSA(exit)
	SUSP_VERSA(exit_group)
	SUSP_VERSA(set_tid_address)
	SUSP_VERSA(unshare)
	SUSP_VERSA(delete_module)
	SUSP_VERSA(timer_getoverrun)
	SUSP_VERSA(timer_delete)
	SUSP_VERSA(syslog)
	SUSP_VERSA(ptrace)
	SUSP_VERSA(sched_setparam)
	SUSP_VERSA(sched_setscheduler)
	SUSP_VERSA(sched_getscheduler)
	SUSP_VERSA(sched_getparam)
	SUSP_VERSA(sched_get_priority_max)
	SUSP_VERSA(sched_get_priority_min)
	SUSP_VERSA(kill)
	SUSP_VERSA(tkill)
	SUSP_VERSA(tgkill)
	SUSP_VERSA(setpriority)
	SUSP_VERSA(getpriority)
	SUSP_VERSA(setregid)
	SUSP_VERSA(setgid)
	SUSP_VERSA(setreuid)
	SUSP_VERSA(setuid)
	SUSP_VERSA(setresuid)
	SUSP_VERSA(getresuid)
	SUSP_VERSA(setresgid)
	SUSP_VERSA(getresgid)
	SUSP_VERSA(setfsuid)
	SUSP_VERSA(setfsgid)
	SUSP_VERSA(setpgid)
	SUSP_VERSA(getpgid)
	SUSP_VERSA(getsid)
	SUSP_VERSA(getgroups)
	SUSP_VERSA(setgroups)
	SUSP_VERSA(sethostname)
	SUSP_VERSA(setdomainname)
	SUSP_VERSA(umask)
	SUSP_VERSA(prctl)
	SUSP_VERSA(getcpu)
	SUSP_VERSA(mq_unlink)
	SUSP_VERSA(msgget)
	SUSP_VERSA(semget)
	SUSP_VERSA(semop)
	SUSP_VERSA(shmget)
	SUSP_VERSA(shmdt)
	SUSP_VERSA(brk)
	SUSP_VERSA(munmap)
	SUSP_VERSA(mremap)
	SUSP_VERSA(request_key)
	SUSP_VERSA(swapon)
	SUSP_VERSA(swapoff)
	SUSP_VERSA(mprotect)
	SUSP_VERSA(msync)
	SUSP_VERSA(mlock)
	SUSP_VERSA(munlock)
	SUSP_VERSA(mlockall)
	SUSP_VERSA(mincore)
	SUSP_VERSA(madvise)
	SUSP_VERSA(remap_file_pages)
	SUSP_VERSA(perf_event_open)
	SUSP_VERSA(prlimit64)
	SUSP_VERSA(fanotify_init)
	SUSP_VERSA(fanotify_mark)
	SUSP_VERSA(name_to_handle_at)
	SUSP_VERSA(syncfs)
	SUSP_VERSA(setns)
	SUSP_VERSA(kcmp)
	SUSP_VERSA(finit_module)
	SUSP_VERSA(open)
	SUSP_VERSA(link)
	SUSP_VERSA(unlink)
	SUSP_VERSA(mknod)
	SUSP_VERSA(chmod)
	SUSP_VERSA(chown)
	SUSP_VERSA(mkdir)
	SUSP_VERSA(rmdir)
	SUSP_VERSA(lchown)
	SUSP_VERSA(access)
	SUSP_VERSA(rename)
	SUSP_VERSA(readlink)
	SUSP_VERSA(symlink)
	SUSP_VERSA(utimes)
	SUSP_VERSA(pipe)
	SUSP_VERSA(dup2)
	SUSP_VERSA(epoll_create)
	SUSP_VERSA(eventfd)
	SUSP_VERSA(signalfd)
	SUSP_VERSA(sendfile)
	SUSP_VERSA(ftruncate)
	SUSP_VERSA(truncate)
	SUSP_VERSA(fcntl)
	SUSP_VERSA(fadvise64)
	SUSP_VERSA(newfstatat)
	SUSP_VERSA(fstatfs)
	SUSP_VERSA(statfs)
	SUSP_VERSA(lseek)
	SUSP_VERSA(alarm)
	SUSP_VERSA(time)
	SUSP_VERSA(utime)
	SUSP_VERSA(creat)
	SUSP_VERSA(getdents)
	SUSP_VERSA(futimesat)
	SUSP_VERSA(select)
	SUSP_VERSA(poll)
	SUSP_VERSA(epoll_wait)
	SUSP_VERSA(ustat)
	SUSP_VERSA(uselib)
}
