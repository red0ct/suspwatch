static int check_perm(const char *sc) {
    printk(KERN_INFO "[Susp]%s accepted for [%s] (%d)", sc, current->comm, current->pid); /* callback needed */
    return 1;
}

SUSP(sys_time,time_t __user *tloc)
asmlinkage long susp_sys_time(time_t __user *tloc) {
	if (check_perm("time")) { return ((sys_time_type)laid_sc_table[__NR_time])(tloc); }
	else { return EINVAL;  }
}

SUSP(sys_alarm,unsigned int seconds)
asmlinkage long susp_sys_alarm(unsigned int seconds) {
	if (check_perm("alarm")) { return ((sys_alarm_type)laid_sc_table[__NR_alarm])(seconds); }
	else { return EINVAL;  }
}

SUSP(sys_getresuid,uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid)
asmlinkage long susp_sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) {
	if (check_perm("getresuid")) { return ((sys_getresuid_type)laid_sc_table[__NR_getresuid])(ruid,euid,suid); }
	else { return EINVAL;  }
}

SUSP(sys_getresgid,gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid)
asmlinkage long susp_sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) {
	if (check_perm("getresgid")) { return ((sys_getresgid_type)laid_sc_table[__NR_getresgid])(rgid,egid,sgid); }
	else { return EINVAL;  }
}

SUSP(sys_getpgid,pid_t pid)
asmlinkage long susp_sys_getpgid(pid_t pid) {
	if (check_perm("getpgid")) { return ((sys_getpgid_type)laid_sc_table[__NR_getpgid])(pid); }
	else { return EINVAL;  }
}

SUSP(sys_getsid,pid_t pid)
asmlinkage long susp_sys_getsid(pid_t pid) {
	if (check_perm("getsid")) { return ((sys_getsid_type)laid_sc_table[__NR_getsid])(pid); }
	else { return EINVAL;  }
}

SUSP(sys_getgroups,int gidsetsize, gid_t __user *grouplist)
asmlinkage long susp_sys_getgroups(int gidsetsize, gid_t __user *grouplist) {
	if (check_perm("getgroups")) { return ((sys_getgroups_type)laid_sc_table[__NR_getgroups])(gidsetsize,grouplist); }
	else { return EINVAL;  }
}

SUSP(sys_setregid,gid_t rgid, gid_t egid)
asmlinkage long susp_sys_setregid(gid_t rgid, gid_t egid) {
	if (check_perm("setregid")) { return ((sys_setregid_type)laid_sc_table[__NR_setregid])(rgid,egid); }
	else { return EINVAL;  }
}

SUSP(sys_setgid,gid_t gid)
asmlinkage long susp_sys_setgid(gid_t gid) {
	if (check_perm("setgid")) { return ((sys_setgid_type)laid_sc_table[__NR_setgid])(gid); }
	else { return EINVAL;  }
}

SUSP(sys_setreuid,uid_t ruid, uid_t euid)
asmlinkage long susp_sys_setreuid(uid_t ruid, uid_t euid) {
	if (check_perm("setreuid")) { return ((sys_setreuid_type)laid_sc_table[__NR_setreuid])(ruid,euid); }
	else { return EINVAL;  }
}

SUSP(sys_setuid,uid_t uid)
asmlinkage long susp_sys_setuid(uid_t uid) {
	if (check_perm("setuid")) { return ((sys_setuid_type)laid_sc_table[__NR_setuid])(uid); }
	else { return EINVAL;  }
}

SUSP(sys_setresuid,uid_t ruid, uid_t euid, uid_t suid)
asmlinkage long susp_sys_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
	if (check_perm("setresuid")) { return ((sys_setresuid_type)laid_sc_table[__NR_setresuid])(ruid,euid,suid); }
	else { return EINVAL;  }
}

SUSP(sys_setresgid,gid_t rgid, gid_t egid, gid_t sgid)
asmlinkage long susp_sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
	if (check_perm("setresgid")) { return ((sys_setresgid_type)laid_sc_table[__NR_setresgid])(rgid,egid,sgid); }
	else { return EINVAL;  }
}

SUSP(sys_setfsuid,uid_t uid)
asmlinkage long susp_sys_setfsuid(uid_t uid) {
	if (check_perm("setfsuid")) { return ((sys_setfsuid_type)laid_sc_table[__NR_setfsuid])(uid); }
	else { return EINVAL;  }
}

SUSP(sys_setfsgid,gid_t gid)
asmlinkage long susp_sys_setfsgid(gid_t gid) {
	if (check_perm("setfsgid")) { return ((sys_setfsgid_type)laid_sc_table[__NR_setfsgid])(gid); }
	else { return EINVAL;  }
}

SUSP(sys_setpgid,pid_t pid, pid_t pgid)
asmlinkage long susp_sys_setpgid(pid_t pid, pid_t pgid) {
	if (check_perm("setpgid")) { return ((sys_setpgid_type)laid_sc_table[__NR_setpgid])(pid,pgid); }
	else { return EINVAL;  }
}

SUSP(sys_setgroups,int gidsetsize, gid_t __user *grouplist)
asmlinkage long susp_sys_setgroups(int gidsetsize, gid_t __user *grouplist) {
	if (check_perm("setgroups")) { return ((sys_setgroups_type)laid_sc_table[__NR_setgroups])(gidsetsize,grouplist); }
	else { return EINVAL;  }
}

SUSP(sys_acct,const char __user *name)
asmlinkage long susp_sys_acct(const char __user *name) {
	if (check_perm("acct")) { return ((sys_acct_type)laid_sc_table[__NR_acct])(name); }
	else { return EINVAL;  }
}

SUSP(sys_capget,cap_user_header_t header, cap_user_data_t dataptr)
asmlinkage long susp_sys_capget(cap_user_header_t header, cap_user_data_t dataptr) {
	if (check_perm("capget")) { return ((sys_capget_type)laid_sc_table[__NR_capget])(header,dataptr); }
	else { return EINVAL;  }
}

SUSP(sys_capset,cap_user_header_t header, const cap_user_data_t data)
asmlinkage long susp_sys_capset(cap_user_header_t header, const cap_user_data_t data) {
	if (check_perm("capset")) { return ((sys_capset_type)laid_sc_table[__NR_capset])(header,data); }
	else { return EINVAL;  }
}

SUSP(sys_personality,unsigned int personality)
asmlinkage long susp_sys_personality(unsigned int personality) {
	if (check_perm("personality")) { return ((sys_personality_type)laid_sc_table[__NR_personality])(personality); }
	else { return EINVAL;  }
}

SUSP(sys_timer_getoverrun,timer_t timer_id)
asmlinkage long susp_sys_timer_getoverrun(timer_t timer_id) {
	if (check_perm("timer_getoverrun")) { return ((sys_timer_getoverrun_type)laid_sc_table[__NR_timer_getoverrun])(timer_id); }
	else { return EINVAL;  }
}

SUSP(sys_timer_delete,timer_t timer_id)
asmlinkage long susp_sys_timer_delete(timer_t timer_id) {
	if (check_perm("timer_delete")) { return ((sys_timer_delete_type)laid_sc_table[__NR_timer_delete])(timer_id); }
	else { return EINVAL;  }
}

SUSP(sys_sched_setscheduler,pid_t pid, int policy, struct sched_param __user *param)
asmlinkage long susp_sys_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param) {
	if (check_perm("sched_setscheduler")) { return ((sys_sched_setscheduler_type)laid_sc_table[__NR_sched_setscheduler])(pid,policy,param); }
	else { return EINVAL;  }
}

SUSP(sys_sched_setparam,pid_t pid, struct sched_param __user *param)
asmlinkage long susp_sys_sched_setparam(pid_t pid, struct sched_param __user *param) {
	if (check_perm("sched_setparam")) { return ((sys_sched_setparam_type)laid_sc_table[__NR_sched_setparam])(pid,param); }
	else { return EINVAL;  }
}

SUSP(sys_sched_getscheduler,pid_t pid)
asmlinkage long susp_sys_sched_getscheduler(pid_t pid) {
	if (check_perm("sched_getscheduler")) { return ((sys_sched_getscheduler_type)laid_sc_table[__NR_sched_getscheduler])(pid); }
	else { return EINVAL;  }
}

SUSP(sys_sched_getparam,pid_t pid, struct sched_param __user *param)
asmlinkage long susp_sys_sched_getparam(pid_t pid, struct sched_param __user *param) {
	if (check_perm("sched_getparam")) { return ((sys_sched_getparam_type)laid_sc_table[__NR_sched_getparam])(pid,param); }
	else { return EINVAL;  }
}

SUSP(sys_sched_get_priority_max,int policy)
asmlinkage long susp_sys_sched_get_priority_max(int policy) {
	if (check_perm("sched_get_priority_max")) { return ((sys_sched_get_priority_max_type)laid_sc_table[__NR_sched_get_priority_max])(policy); }
	else { return EINVAL;  }
}

SUSP(sys_sched_get_priority_min,int policy)
asmlinkage long susp_sys_sched_get_priority_min(int policy) {
	if (check_perm("sched_get_priority_min")) { return ((sys_sched_get_priority_min_type)laid_sc_table[__NR_sched_get_priority_min])(policy); }
	else { return EINVAL;  }
}

SUSP(sys_setpriority,int which, int who, int niceval)
asmlinkage long susp_sys_setpriority(int which, int who, int niceval) {
	if (check_perm("setpriority")) { return ((sys_setpriority_type)laid_sc_table[__NR_setpriority])(which,who,niceval); }
	else { return EINVAL;  }
}

SUSP(sys_getpriority,int which, int who)
asmlinkage long susp_sys_getpriority(int which, int who) {
	if (check_perm("getpriority")) { return ((sys_getpriority_type)laid_sc_table[__NR_getpriority])(which,who); }
	else { return EINVAL;  }
}

SUSP(sys_exit,int error_code)
asmlinkage long susp_sys_exit(int error_code) {
	if (check_perm("exit")) { return ((sys_exit_type)laid_sc_table[__NR_exit])(error_code); }
	else { return EINVAL;  }
}

SUSP(sys_exit_group,int error_code)
asmlinkage long susp_sys_exit_group(int error_code) {
	if (check_perm("exit_group")) { return ((sys_exit_group_type)laid_sc_table[__NR_exit_group])(error_code); }
	else { return EINVAL;  }
}

SUSP(sys_wait4,pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru)
asmlinkage long susp_sys_wait4(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru) {
	if (check_perm("wait4")) { return ((sys_wait4_type)laid_sc_table[__NR_wait4])(pid,stat_addr,options,ru); }
	else { return EINVAL;  }
}

SUSP(sys_set_tid_address,int __user *tidptr)
asmlinkage long susp_sys_set_tid_address(int __user *tidptr) {
	if (check_perm("set_tid_address")) { return ((sys_set_tid_address_type)laid_sc_table[__NR_set_tid_address])(tidptr); }
	else { return EINVAL;  }
}

SUSP(sys_delete_module,const char __user *name_user, unsigned int flags)
asmlinkage long susp_sys_delete_module(const char __user *name_user, unsigned int flags) {
	if (check_perm("delete_module")) { return ((sys_delete_module_type)laid_sc_table[__NR_delete_module])(name_user,flags); }
	else { return EINVAL;  }
}

SUSP(sys_kill,int pid, int sig)
asmlinkage long susp_sys_kill(int pid, int sig) {
	if (check_perm("kill")) { return ((sys_kill_type)laid_sc_table[__NR_kill])(pid,sig); }
	else { return EINVAL;  }
}

SUSP(sys_tgkill,int tgid, int pid, int sig)
asmlinkage long susp_sys_tgkill(int tgid, int pid, int sig) {
	if (check_perm("tgkill")) { return ((sys_tgkill_type)laid_sc_table[__NR_tgkill])(tgid,pid,sig); }
	else { return EINVAL;  }
}

SUSP(sys_tkill,int pid, int sig)
asmlinkage long susp_sys_tkill(int pid, int sig) {
	if (check_perm("tkill")) { return ((sys_tkill_type)laid_sc_table[__NR_tkill])(pid,sig); }
	else { return EINVAL;  }
}

SUSP(sys_fsync,unsigned int fd)
asmlinkage long susp_sys_fsync(unsigned int fd) {
	if (check_perm("fsync")) { return ((sys_fsync_type)laid_sc_table[__NR_fsync])(fd); }
	else { return EINVAL;  }
}

SUSP(sys_fdatasync,unsigned int fd)
asmlinkage long susp_sys_fdatasync(unsigned int fd) {
	if (check_perm("fdatasync")) { return ((sys_fdatasync_type)laid_sc_table[__NR_fdatasync])(fd); }
	else { return EINVAL;  }
}

SUSP(sys_truncate,const char __user *path, long length)
asmlinkage long susp_sys_truncate(const char __user *path, long length) {
	if (check_perm("truncate")) { return ((sys_truncate_type)laid_sc_table[__NR_truncate])(path,length); }
	else { return EINVAL;  }
}

SUSP(sys_ftruncate,unsigned int fd, unsigned long length)
asmlinkage long susp_sys_ftruncate(unsigned int fd, unsigned long length) {
	if (check_perm("ftruncate")) { return ((sys_ftruncate_type)laid_sc_table[__NR_ftruncate])(fd,length); }
	else { return EINVAL;  }
}

SUSP(sys_statfs,const char __user * path, struct statfs __user *buf)
asmlinkage long susp_sys_statfs(const char __user * path, struct statfs __user *buf) {
	if (check_perm("statfs")) { return ((sys_statfs_type)laid_sc_table[__NR_statfs])(path,buf); }
	else { return EINVAL;  }
}

SUSP(sys_fstatfs,unsigned int fd, struct statfs __user *buf)
asmlinkage long susp_sys_fstatfs(unsigned int fd, struct statfs __user *buf) {
	if (check_perm("fstatfs")) { return ((sys_fstatfs_type)laid_sc_table[__NR_fstatfs])(fd,buf); }
	else { return EINVAL;  }
}

SUSP(sys_ustat,unsigned dev, struct ustat __user *ubuf)
asmlinkage long susp_sys_ustat(unsigned dev, struct ustat __user *ubuf) {
	if (check_perm("ustat")) { return ((sys_ustat_type)laid_sc_table[__NR_ustat])(dev,ubuf); }
	else { return EINVAL;  }
}

SUSP(sys_listxattr,const char __user *path, char __user *list, size_t size)
asmlinkage long susp_sys_listxattr(const char __user *path, char __user *list, size_t size) {
	if (check_perm("listxattr")) { return ((sys_listxattr_type)laid_sc_table[__NR_listxattr])(path,list,size); }
	else { return EINVAL;  }
}

SUSP(sys_llistxattr,const char __user *path, char __user *list, size_t size)
asmlinkage long susp_sys_llistxattr(const char __user *path, char __user *list, size_t size) {
	if (check_perm("llistxattr")) { return ((sys_llistxattr_type)laid_sc_table[__NR_llistxattr])(path,list,size); }
	else { return EINVAL;  }
}

SUSP(sys_flistxattr,int fd, char __user *list, size_t size)
asmlinkage long susp_sys_flistxattr(int fd, char __user *list, size_t size) {
	if (check_perm("flistxattr")) { return ((sys_flistxattr_type)laid_sc_table[__NR_flistxattr])(fd,list,size); }
	else { return EINVAL;  }
}

SUSP(sys_removexattr,const char __user *path, const char __user *name)
asmlinkage long susp_sys_removexattr(const char __user *path, const char __user *name) {
	if (check_perm("removexattr")) { return ((sys_removexattr_type)laid_sc_table[__NR_removexattr])(path,name); }
	else { return EINVAL;  }
}

SUSP(sys_lremovexattr,const char __user *path, const char __user *name)
asmlinkage long susp_sys_lremovexattr(const char __user *path, const char __user *name) {
	if (check_perm("lremovexattr")) { return ((sys_lremovexattr_type)laid_sc_table[__NR_lremovexattr])(path,name); }
	else { return EINVAL;  }
}

SUSP(sys_fremovexattr,int fd, const char __user *name)
asmlinkage long susp_sys_fremovexattr(int fd, const char __user *name) {
	if (check_perm("fremovexattr")) { return ((sys_fremovexattr_type)laid_sc_table[__NR_fremovexattr])(fd,name); }
	else { return EINVAL;  }
}

SUSP(sys_brk,unsigned long brk)
asmlinkage long susp_sys_brk(unsigned long brk) {
	if (check_perm("brk")) { return ((sys_brk_type)laid_sc_table[__NR_brk])(brk); }
	else { return EINVAL;  }
}

SUSP(sys_mprotect,unsigned long start, size_t len, unsigned long prot)
asmlinkage long susp_sys_mprotect(unsigned long start, size_t len, unsigned long prot) {
	if (check_perm("mprotect")) { return ((sys_mprotect_type)laid_sc_table[__NR_mprotect])(start,len,prot); }
	else { return EINVAL;  }
}

SUSP(sys_mremap,unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
asmlinkage long susp_sys_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr) {
	if (check_perm("mremap")) { return ((sys_mremap_type)laid_sc_table[__NR_mremap])(addr,old_len,new_len,flags,new_addr); }
	else { return EINVAL;  }
}

SUSP(sys_remap_file_pages,unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)
asmlinkage long susp_sys_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags) {
	if (check_perm("remap_file_pages")) { return ((sys_remap_file_pages_type)laid_sc_table[__NR_remap_file_pages])(start,size,prot,pgoff,flags); }
	else { return EINVAL;  }
}

SUSP(sys_msync,unsigned long start, size_t len, int flags)
asmlinkage long susp_sys_msync(unsigned long start, size_t len, int flags) {
	if (check_perm("msync")) { return ((sys_msync_type)laid_sc_table[__NR_msync])(start,len,flags); }
	else { return EINVAL;  }
}

SUSP(sys_fadvise64,int fd, loff_t offset, size_t len, int advice)
asmlinkage long susp_sys_fadvise64(int fd, loff_t offset, size_t len, int advice) {
	if (check_perm("fadvise64")) { return ((sys_fadvise64_type)laid_sc_table[__NR_fadvise64])(fd,offset,len,advice); }
	else { return EINVAL;  }
}

SUSP(sys_munmap,unsigned long addr, size_t len)
asmlinkage long susp_sys_munmap(unsigned long addr, size_t len) {
	if (check_perm("munmap")) { return ((sys_munmap_type)laid_sc_table[__NR_munmap])(addr,len); }
	else { return EINVAL;  }
}

SUSP(sys_mlock,unsigned long start, size_t len)
asmlinkage long susp_sys_mlock(unsigned long start, size_t len) {
	if (check_perm("mlock")) { return ((sys_mlock_type)laid_sc_table[__NR_mlock])(start,len); }
	else { return EINVAL;  }
}

SUSP(sys_munlock,unsigned long start, size_t len)
asmlinkage long susp_sys_munlock(unsigned long start, size_t len) {
	if (check_perm("munlock")) { return ((sys_munlock_type)laid_sc_table[__NR_munlock])(start,len); }
	else { return EINVAL;  }
}

SUSP(sys_mlockall,int flags)
asmlinkage long susp_sys_mlockall(int flags) {
	if (check_perm("mlockall")) { return ((sys_mlockall_type)laid_sc_table[__NR_mlockall])(flags); }
	else { return EINVAL;  }
}

SUSP(sys_madvise,unsigned long start, size_t len, int behavior)
asmlinkage long susp_sys_madvise(unsigned long start, size_t len, int behavior) {
	if (check_perm("madvise")) { return ((sys_madvise_type)laid_sc_table[__NR_madvise])(start,len,behavior); }
	else { return EINVAL;  }
}

SUSP(sys_mincore,unsigned long start, size_t len, unsigned char __user * vec)
asmlinkage long susp_sys_mincore(unsigned long start, size_t len, unsigned char __user * vec) {
	if (check_perm("mincore")) { return ((sys_mincore_type)laid_sc_table[__NR_mincore])(start,len,vec); }
	else { return EINVAL;  }
}

SUSP(sys_pivot_root,const char __user *new_root, const char __user *put_old)
asmlinkage long susp_sys_pivot_root(const char __user *new_root, const char __user *put_old) {
	if (check_perm("pivot_root")) { return ((sys_pivot_root_type)laid_sc_table[__NR_pivot_root])(new_root,put_old); }
	else { return EINVAL;  }
}

SUSP(sys_chroot,const char __user *filename)
asmlinkage long susp_sys_chroot(const char __user *filename) {
	if (check_perm("chroot")) { return ((sys_chroot_type)laid_sc_table[__NR_chroot])(filename); }
	else { return EINVAL;  }
}

SUSP(sys_mknod,const char __user *filename, umode_t mode, unsigned dev)
asmlinkage long susp_sys_mknod(const char __user *filename, umode_t mode, unsigned dev) {
	if (check_perm("mknod")) { return ((sys_mknod_type)laid_sc_table[__NR_mknod])(filename,mode,dev); }
	else { return EINVAL;  }
}

SUSP(sys_link,const char __user *oldname, const char __user *newname)
asmlinkage long susp_sys_link(const char __user *oldname, const char __user *newname) {
	if (check_perm("link")) { return ((sys_link_type)laid_sc_table[__NR_link])(oldname,newname); }
	else { return EINVAL;  }
}

SUSP(sys_symlink,const char __user *old, const char __user *new)
asmlinkage long susp_sys_symlink(const char __user *old, const char __user *new) {
	if (check_perm("symlink")) { return ((sys_symlink_type)laid_sc_table[__NR_symlink])(old,new); }
	else { return EINVAL;  }
}

SUSP(sys_unlink,const char __user *pathname)
asmlinkage long susp_sys_unlink(const char __user *pathname) {
	if (check_perm("unlink")) { return ((sys_unlink_type)laid_sc_table[__NR_unlink])(pathname); }
	else { return EINVAL;  }
}

SUSP(sys_rename,const char __user *oldname, const char __user *newname)
asmlinkage long susp_sys_rename(const char __user *oldname, const char __user *newname) {
	if (check_perm("rename")) { return ((sys_rename_type)laid_sc_table[__NR_rename])(oldname,newname); }
	else { return EINVAL;  }
}

SUSP(sys_chmod,const char __user *filename, umode_t mode)
asmlinkage long susp_sys_chmod(const char __user *filename, umode_t mode) {
	if (check_perm("chmod")) { return ((sys_chmod_type)laid_sc_table[__NR_chmod])(filename,mode); }
	else { return EINVAL;  }
}

SUSP(sys_fchmod,unsigned int fd, umode_t mode)
asmlinkage long susp_sys_fchmod(unsigned int fd, umode_t mode) {
	if (check_perm("fchmod")) { return ((sys_fchmod_type)laid_sc_table[__NR_fchmod])(fd,mode); }
	else { return EINVAL;  }
}

SUSP(sys_fcntl,unsigned int fd, unsigned int cmd, unsigned long arg)
asmlinkage long susp_sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg) {
	if (check_perm("fcntl")) { return ((sys_fcntl_type)laid_sc_table[__NR_fcntl])(fd,cmd,arg); }
	else { return EINVAL;  }
}

SUSP(sys_pipe,int __user *fildes)
asmlinkage long susp_sys_pipe(int __user *fildes) {
	if (check_perm("pipe")) { return ((sys_pipe_type)laid_sc_table[__NR_pipe])(fildes); }
	else { return EINVAL;  }
}

SUSP(sys_pipe2,int __user *fildes, int flags)
asmlinkage long susp_sys_pipe2(int __user *fildes, int flags) {
	if (check_perm("pipe2")) { return ((sys_pipe2_type)laid_sc_table[__NR_pipe2])(fildes,flags); }
	else { return EINVAL;  }
}

SUSP(sys_dup,unsigned int fildes)
asmlinkage long susp_sys_dup(unsigned int fildes) {
	if (check_perm("dup")) { return ((sys_dup_type)laid_sc_table[__NR_dup])(fildes); }
	else { return EINVAL;  }
}

SUSP(sys_dup2,unsigned int oldfd, unsigned int newfd)
asmlinkage long susp_sys_dup2(unsigned int oldfd, unsigned int newfd) {
	if (check_perm("dup2")) { return ((sys_dup2_type)laid_sc_table[__NR_dup2])(oldfd,newfd); }
	else { return EINVAL;  }
}

SUSP(sys_dup3,unsigned int oldfd, unsigned int newfd, int flags)
asmlinkage long susp_sys_dup3(unsigned int oldfd, unsigned int newfd, int flags) {
	if (check_perm("dup3")) { return ((sys_dup3_type)laid_sc_table[__NR_dup3])(oldfd,newfd,flags); }
	else { return EINVAL;  }
}

SUSP(sys_flock,unsigned int fd, unsigned int cmd)
asmlinkage long susp_sys_flock(unsigned int fd, unsigned int cmd) {
	if (check_perm("flock")) { return ((sys_flock_type)laid_sc_table[__NR_flock])(fd,cmd); }
	else { return EINVAL;  }
}

SUSP(sys_io_destroy,aio_context_t ctx)
asmlinkage long susp_sys_io_destroy(aio_context_t ctx) {
	if (check_perm("io_destroy")) { return ((sys_io_destroy_type)laid_sc_table[__NR_io_destroy])(ctx); }
	else { return EINVAL;  }
}

SUSP(sys_io_cancel,aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result)
asmlinkage long susp_sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result) {
	if (check_perm("io_cancel")) { return ((sys_io_cancel_type)laid_sc_table[__NR_io_cancel])(ctx_id,iocb,result); }
	else { return EINVAL;  }
}

SUSP(sys_sendfile,int out_fd, int in_fd, off_t __user *offset, size_t count)
asmlinkage long susp_sys_sendfile(int out_fd, int in_fd, off_t __user *offset, size_t count) {
	if (check_perm("sendfile")) { return ((sys_sendfile_type)laid_sc_table[__NR_sendfile])(out_fd,in_fd,offset,count); }
	else { return EINVAL;  }
}

SUSP(sys_readlink,const char __user *path, char __user *buf, int bufsiz)
asmlinkage long susp_sys_readlink(const char __user *path, char __user *buf, int bufsiz) {
	if (check_perm("readlink")) { return ((sys_readlink_type)laid_sc_table[__NR_readlink])(path,buf,bufsiz); }
	else { return EINVAL;  }
}

SUSP(sys_creat,const char __user *pathname, umode_t mode)
asmlinkage long susp_sys_creat(const char __user *pathname, umode_t mode) {
	if (check_perm("creat")) { return ((sys_creat_type)laid_sc_table[__NR_creat])(pathname,mode); }
	else { return EINVAL;  }
}

SUSP(sys_open,const char __user *filename, int flags, umode_t mode)
asmlinkage long susp_sys_open(const char __user *filename, int flags, umode_t mode) {
	if (check_perm("open")) { return ((sys_open_type)laid_sc_table[__NR_open])(filename,flags,mode); }
	else { return EINVAL;  }
}

SUSP(sys_close,unsigned int fd)
asmlinkage long susp_sys_close(unsigned int fd) {
	if (check_perm("close")) { return ((sys_close_type)laid_sc_table[__NR_close])(fd); }
	else { return EINVAL;  }
}

SUSP(sys_access,const char __user *filename, int mode)
asmlinkage long susp_sys_access(const char __user *filename, int mode) {
	if (check_perm("access")) { return ((sys_access_type)laid_sc_table[__NR_access])(filename,mode); }
	else { return EINVAL;  }
}

SUSP(sys_chown,const char __user *filename, uid_t user, gid_t group)
asmlinkage long susp_sys_chown(const char __user *filename, uid_t user, gid_t group) {
	if (check_perm("chown")) { return ((sys_chown_type)laid_sc_table[__NR_chown])(filename,user,group); }
	else { return EINVAL;  }
}

SUSP(sys_lchown,const char __user *filename, uid_t user, gid_t group)
asmlinkage long susp_sys_lchown(const char __user *filename, uid_t user, gid_t group) {
	if (check_perm("lchown")) { return ((sys_lchown_type)laid_sc_table[__NR_lchown])(filename,user,group); }
	else { return EINVAL;  }
}

SUSP(sys_fchown,unsigned int fd, uid_t user, gid_t group)
asmlinkage long susp_sys_fchown(unsigned int fd, uid_t user, gid_t group) {
	if (check_perm("fchown")) { return ((sys_fchown_type)laid_sc_table[__NR_fchown])(fd,user,group); }
	else { return EINVAL;  }
}

SUSP(sys_utime,char __user *filename, struct utimbuf __user *times)
asmlinkage long susp_sys_utime(char __user *filename, struct utimbuf __user *times) {
	if (check_perm("utime")) { return ((sys_utime_type)laid_sc_table[__NR_utime])(filename,times); }
	else { return EINVAL;  }
}

SUSP(sys_utimes,char __user *filename, struct timeval __user *utimes)
asmlinkage long susp_sys_utimes(char __user *filename, struct timeval __user *utimes) {
	if (check_perm("utimes")) { return ((sys_utimes_type)laid_sc_table[__NR_utimes])(filename,utimes); }
	else { return EINVAL;  }
}

SUSP(sys_lseek,unsigned int fd, off_t offset, unsigned int whence)
asmlinkage long susp_sys_lseek(unsigned int fd, off_t offset, unsigned int whence) {
	if (check_perm("lseek")) { return ((sys_lseek_type)laid_sc_table[__NR_lseek])(fd,offset,whence); }
	else { return EINVAL;  }
}

SUSP(sys_read,unsigned int fd, char __user *buf, size_t count)
asmlinkage long susp_sys_read(unsigned int fd, char __user *buf, size_t count) {
	if (check_perm("read")) { return ((sys_read_type)laid_sc_table[__NR_read])(fd,buf,count); }
	else { return EINVAL;  }
}

SUSP(sys_write,unsigned int fd, const char __user *buf, size_t count)
asmlinkage long susp_sys_write(unsigned int fd, const char __user *buf, size_t count) {
	if (check_perm("write")) { return ((sys_write_type)laid_sc_table[__NR_write])(fd,buf,count); }
	else { return EINVAL;  }
}

SUSP(sys_getcwd,char __user *buf, unsigned long size)
asmlinkage long susp_sys_getcwd(char __user *buf, unsigned long size) {
	if (check_perm("getcwd")) { return ((sys_getcwd_type)laid_sc_table[__NR_getcwd])(buf,size); }
	else { return EINVAL;  }
}

SUSP(sys_mkdir,const char __user *pathname, umode_t mode)
asmlinkage long susp_sys_mkdir(const char __user *pathname, umode_t mode) {
	if (check_perm("mkdir")) { return ((sys_mkdir_type)laid_sc_table[__NR_mkdir])(pathname,mode); }
	else { return EINVAL;  }
}

SUSP(sys_chdir,const char __user *filename)
asmlinkage long susp_sys_chdir(const char __user *filename) {
	if (check_perm("chdir")) { return ((sys_chdir_type)laid_sc_table[__NR_chdir])(filename); }
	else { return EINVAL;  }
}

SUSP(sys_fchdir,unsigned int fd)
asmlinkage long susp_sys_fchdir(unsigned int fd) {
	if (check_perm("fchdir")) { return ((sys_fchdir_type)laid_sc_table[__NR_fchdir])(fd); }
	else { return EINVAL;  }
}

SUSP(sys_rmdir,const char __user *pathname)
asmlinkage long susp_sys_rmdir(const char __user *pathname) {
	if (check_perm("rmdir")) { return ((sys_rmdir_type)laid_sc_table[__NR_rmdir])(pathname); }
	else { return EINVAL;  }
}

SUSP(sys_getdents,unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
asmlinkage long susp_sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
	if (check_perm("getdents")) { return ((sys_getdents_type)laid_sc_table[__NR_getdents])(fd,dirent,count); }
	else { return EINVAL;  }
}

SUSP(sys_poll,struct pollfd __user *ufds, unsigned int nfds, int timeout)
asmlinkage long susp_sys_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout) {
	if (check_perm("poll")) { return ((sys_poll_type)laid_sc_table[__NR_poll])(ufds,nfds,timeout); }
	else { return EINVAL;  }
}

SUSP(sys_select,int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
asmlinkage long susp_sys_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp) {
	if (check_perm("select")) { return ((sys_select_type)laid_sc_table[__NR_select])(n,inp,outp,exp,tvp); }
	else { return EINVAL;  }
}

SUSP(sys_epoll_create,int size)
asmlinkage long susp_sys_epoll_create(int size) {
	if (check_perm("epoll_create")) { return ((sys_epoll_create_type)laid_sc_table[__NR_epoll_create])(size); }
	else { return EINVAL;  }
}

SUSP(sys_epoll_create1,int flags)
asmlinkage long susp_sys_epoll_create1(int flags) {
	if (check_perm("epoll_create1")) { return ((sys_epoll_create1_type)laid_sc_table[__NR_epoll_create1])(flags); }
	else { return EINVAL;  }
}

SUSP(sys_epoll_ctl,int epfd, int op, int fd, struct epoll_event __user *event)
asmlinkage long susp_sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event) {
	if (check_perm("epoll_ctl")) { return ((sys_epoll_ctl_type)laid_sc_table[__NR_epoll_ctl])(epfd,op,fd,event); }
	else { return EINVAL;  }
}

SUSP(sys_epoll_wait,int epfd, struct epoll_event __user *events, int maxevents, int timeout)
asmlinkage long susp_sys_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout) {
	if (check_perm("epoll_wait")) { return ((sys_epoll_wait_type)laid_sc_table[__NR_epoll_wait])(epfd,events,maxevents,timeout); }
	else { return EINVAL;  }
}

SUSP(sys_sethostname,char __user *name, int len)
asmlinkage long susp_sys_sethostname(char __user *name, int len) {
	if (check_perm("sethostname")) { return ((sys_sethostname_type)laid_sc_table[__NR_sethostname])(name,len); }
	else { return EINVAL;  }
}

SUSP(sys_setdomainname,char __user *name, int len)
asmlinkage long susp_sys_setdomainname(char __user *name, int len) {
	if (check_perm("setdomainname")) { return ((sys_setdomainname_type)laid_sc_table[__NR_setdomainname])(name,len); }
	else { return EINVAL;  }
}

SUSP(sys_prlimit64,pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim)
asmlinkage long susp_sys_prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim) {
	if (check_perm("prlimit64")) { return ((sys_prlimit64_type)laid_sc_table[__NR_prlimit64])(pid,resource,new_rlim,old_rlim); }
	else { return EINVAL;  }
}

SUSP(sys_umask,int mask)
asmlinkage long susp_sys_umask(int mask) {
	if (check_perm("umask")) { return ((sys_umask_type)laid_sc_table[__NR_umask])(mask); }
	else { return EINVAL;  }
}

SUSP(sys_msgget,key_t key, int msgflg)
asmlinkage long susp_sys_msgget(key_t key, int msgflg) {
	if (check_perm("msgget")) { return ((sys_msgget_type)laid_sc_table[__NR_msgget])(key,msgflg); }
	else { return EINVAL;  }
}

SUSP(sys_semget,key_t key, int nsems, int semflg)
asmlinkage long susp_sys_semget(key_t key, int nsems, int semflg) {
	if (check_perm("semget")) { return ((sys_semget_type)laid_sc_table[__NR_semget])(key,nsems,semflg); }
	else { return EINVAL;  }
}

SUSP(sys_semop,int semid, struct sembuf __user *sops, unsigned nsops)
asmlinkage long susp_sys_semop(int semid, struct sembuf __user *sops, unsigned nsops) {
	if (check_perm("semop")) { return ((sys_semop_type)laid_sc_table[__NR_semop])(semid,sops,nsops); }
	else { return EINVAL;  }
}

SUSP(sys_shmget,key_t key, size_t size, int flag)
asmlinkage long susp_sys_shmget(key_t key, size_t size, int flag) {
	if (check_perm("shmget")) { return ((sys_shmget_type)laid_sc_table[__NR_shmget])(key,size,flag); }
	else { return EINVAL;  }
}

SUSP(sys_shmdt,char __user *shmaddr)
asmlinkage long susp_sys_shmdt(char __user *shmaddr) {
	if (check_perm("shmdt")) { return ((sys_shmdt_type)laid_sc_table[__NR_shmdt])(shmaddr); }
	else { return EINVAL;  }
}

SUSP(sys_mq_unlink,const char __user *name)
asmlinkage long susp_sys_mq_unlink(const char __user *name) {
	if (check_perm("mq_unlink")) { return ((sys_mq_unlink_type)laid_sc_table[__NR_mq_unlink])(name); }
	else { return EINVAL;  }
}

SUSP(sys_prctl,int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
asmlinkage long susp_sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
	if (check_perm("prctl")) { return ((sys_prctl_type)laid_sc_table[__NR_prctl])(option,arg2,arg3,arg4,arg5); }
	else { return EINVAL;  }
}

SUSP(sys_swapon,const char __user *specialfile, int swap_flags)
asmlinkage long susp_sys_swapon(const char __user *specialfile, int swap_flags) {
	if (check_perm("swapon")) { return ((sys_swapon_type)laid_sc_table[__NR_swapon])(specialfile,swap_flags); }
	else { return EINVAL;  }
}

SUSP(sys_swapoff,const char __user *specialfile)
asmlinkage long susp_sys_swapoff(const char __user *specialfile) {
	if (check_perm("swapoff")) { return ((sys_swapoff_type)laid_sc_table[__NR_swapoff])(specialfile); }
	else { return EINVAL;  }
}

SUSP(sys_syslog,int type, char __user *buf, int len)
asmlinkage long susp_sys_syslog(int type, char __user *buf, int len) {
	if (check_perm("syslog")) { return ((sys_syslog_type)laid_sc_table[__NR_syslog])(type,buf,len); }
	else { return EINVAL;  }
}

SUSP(sys_uselib,const char __user *library)
asmlinkage long susp_sys_uselib(const char __user *library) {
	if (check_perm("uselib")) { return ((sys_uselib_type)laid_sc_table[__NR_uselib])(library); }
	else { return EINVAL;  }
}

SUSP(sys_ptrace,long request, long pid, unsigned long addr, unsigned long data)
asmlinkage long susp_sys_ptrace(long request, long pid, unsigned long addr, unsigned long data) {
	if (check_perm("ptrace")) { return ((sys_ptrace_type)laid_sc_table[__NR_ptrace])(request,pid,addr,data); }
	else { return EINVAL;  }
}

SUSP(sys_request_key,const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid)
asmlinkage long susp_sys_request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid) {
	if (check_perm("request_key")) { return ((sys_request_key_type)laid_sc_table[__NR_request_key])(_type,_description,_callout_info,destringid); }
	else { return EINVAL;  }
}

SUSP(sys_ioprio_set,int which, int who, int ioprio)
asmlinkage long susp_sys_ioprio_set(int which, int who, int ioprio) {
	if (check_perm("ioprio_set")) { return ((sys_ioprio_set_type)laid_sc_table[__NR_ioprio_set])(which,who,ioprio); }
	else { return EINVAL;  }
}

SUSP(sys_ioprio_get,int which, int who)
asmlinkage long susp_sys_ioprio_get(int which, int who) {
	if (check_perm("ioprio_get")) { return ((sys_ioprio_get_type)laid_sc_table[__NR_ioprio_get])(which,who); }
	else { return EINVAL;  }
}

SUSP(sys_inotify_init1,int flags)
asmlinkage long susp_sys_inotify_init1(int flags) {
	if (check_perm("inotify_init1")) { return ((sys_inotify_init1_type)laid_sc_table[__NR_inotify_init1])(flags); }
	else { return EINVAL;  }
}

SUSP(sys_inotify_add_watch,int fd, const char __user *path, u32 mask)
asmlinkage long susp_sys_inotify_add_watch(int fd, const char __user *path, u32 mask) {
	if (check_perm("inotify_add_watch")) { return ((sys_inotify_add_watch_type)laid_sc_table[__NR_inotify_add_watch])(fd,path,mask); }
	else { return EINVAL;  }
}

SUSP(sys_inotify_rm_watch,int fd, __s32 wd)
asmlinkage long susp_sys_inotify_rm_watch(int fd, __s32 wd) {
	if (check_perm("inotify_rm_watch")) { return ((sys_inotify_rm_watch_type)laid_sc_table[__NR_inotify_rm_watch])(fd,wd); }
	else { return EINVAL;  }
}

SUSP(sys_mknodat,int dfd, const char __user * filename, umode_t mode, unsigned dev)
asmlinkage long susp_sys_mknodat(int dfd, const char __user * filename, umode_t mode, unsigned dev) {
	if (check_perm("mknodat")) { return ((sys_mknodat_type)laid_sc_table[__NR_mknodat])(dfd,filename,mode,dev); }
	else { return EINVAL;  }
}

SUSP(sys_mkdirat,int dfd, const char __user * pathname, umode_t mode)
asmlinkage long susp_sys_mkdirat(int dfd, const char __user * pathname, umode_t mode) {
	if (check_perm("mkdirat")) { return ((sys_mkdirat_type)laid_sc_table[__NR_mkdirat])(dfd,pathname,mode); }
	else { return EINVAL;  }
}

SUSP(sys_unlinkat,int dfd, const char __user * pathname, int flag)
asmlinkage long susp_sys_unlinkat(int dfd, const char __user * pathname, int flag) {
	if (check_perm("unlinkat")) { return ((sys_unlinkat_type)laid_sc_table[__NR_unlinkat])(dfd,pathname,flag); }
	else { return EINVAL;  }
}

SUSP(sys_symlinkat,const char __user * oldname, int newdfd, const char __user * newname)
asmlinkage long susp_sys_symlinkat(const char __user * oldname, int newdfd, const char __user * newname) {
	if (check_perm("symlinkat")) { return ((sys_symlinkat_type)laid_sc_table[__NR_symlinkat])(oldname,newdfd,newname); }
	else { return EINVAL;  }
}

SUSP(sys_linkat,int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags)
asmlinkage long susp_sys_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags) {
	if (check_perm("linkat")) { return ((sys_linkat_type)laid_sc_table[__NR_linkat])(olddfd,oldname,newdfd,newname,flags); }
	else { return EINVAL;  }
}

SUSP(sys_renameat,int olddfd, const char __user * oldname, int newdfd, const char __user * newname)
asmlinkage long susp_sys_renameat(int olddfd, const char __user * oldname, int newdfd, const char __user * newname) {
	if (check_perm("renameat")) { return ((sys_renameat_type)laid_sc_table[__NR_renameat])(olddfd,oldname,newdfd,newname); }
	else { return EINVAL;  }
}

SUSP(sys_futimesat,int dfd, const char __user *filename, struct timeval __user *utimes)
asmlinkage long susp_sys_futimesat(int dfd, const char __user *filename, struct timeval __user *utimes) {
	if (check_perm("futimesat")) { return ((sys_futimesat_type)laid_sc_table[__NR_futimesat])(dfd,filename,utimes); }
	else { return EINVAL;  }
}

SUSP(sys_faccessat,int dfd, const char __user *filename, int mode)
asmlinkage long susp_sys_faccessat(int dfd, const char __user *filename, int mode) {
	if (check_perm("faccessat")) { return ((sys_faccessat_type)laid_sc_table[__NR_faccessat])(dfd,filename,mode); }
	else { return EINVAL;  }
}

SUSP(sys_fchmodat,int dfd, const char __user * filename, umode_t mode)
asmlinkage long susp_sys_fchmodat(int dfd, const char __user * filename, umode_t mode) {
	if (check_perm("fchmodat")) { return ((sys_fchmodat_type)laid_sc_table[__NR_fchmodat])(dfd,filename,mode); }
	else { return EINVAL;  }
}

SUSP(sys_fchownat,int dfd, const char __user *filename, uid_t user, gid_t group, int flag)
asmlinkage long susp_sys_fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag) {
	if (check_perm("fchownat")) { return ((sys_fchownat_type)laid_sc_table[__NR_fchownat])(dfd,filename,user,group,flag); }
	else { return EINVAL;  }
}

SUSP(sys_newfstatat,int dfd, const char __user *filename, struct stat __user *statbuf, int flag)
asmlinkage long susp_sys_newfstatat(int dfd, const char __user *filename, struct stat __user *statbuf, int flag) {
	if (check_perm("newfstatat")) { return ((sys_newfstatat_type)laid_sc_table[__NR_newfstatat])(dfd,filename,statbuf,flag); }
	else { return EINVAL;  }
}

SUSP(sys_readlinkat,int dfd, const char __user *path, char __user *buf, int bufsiz)
asmlinkage long susp_sys_readlinkat(int dfd, const char __user *path, char __user *buf, int bufsiz) {
	if (check_perm("readlinkat")) { return ((sys_readlinkat_type)laid_sc_table[__NR_readlinkat])(dfd,path,buf,bufsiz); }
	else { return EINVAL;  }
}

SUSP(sys_unshare,unsigned long unshare_flags)
asmlinkage long susp_sys_unshare(unsigned long unshare_flags) {
	if (check_perm("unshare")) { return ((sys_unshare_type)laid_sc_table[__NR_unshare])(unshare_flags); }
	else { return EINVAL;  }
}

SUSP(sys_splice,int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags)
asmlinkage long susp_sys_splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags) {
	if (check_perm("splice")) { return ((sys_splice_type)laid_sc_table[__NR_splice])(fd_in,off_in,fd_out,off_out,len,flags); }
	else { return EINVAL;  }
}

SUSP(sys_tee,int fdin, int fdout, size_t len, unsigned int flags)
asmlinkage long susp_sys_tee(int fdin, int fdout, size_t len, unsigned int flags) {
	if (check_perm("tee")) { return ((sys_tee_type)laid_sc_table[__NR_tee])(fdin,fdout,len,flags); }
	else { return EINVAL;  }
}

SUSP(sys_getcpu,unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache)
asmlinkage long susp_sys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache) {
	if (check_perm("getcpu")) { return ((sys_getcpu_type)laid_sc_table[__NR_getcpu])(cpu,node,cache); }
	else { return EINVAL;  }
}

SUSP(sys_signalfd,int ufd, sigset_t __user *user_mask, size_t sizemask)
asmlinkage long susp_sys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask) {
	if (check_perm("signalfd")) { return ((sys_signalfd_type)laid_sc_table[__NR_signalfd])(ufd,user_mask,sizemask); }
	else { return EINVAL;  }
}

SUSP(sys_timerfd_create,int clockid, int flags)
asmlinkage long susp_sys_timerfd_create(int clockid, int flags) {
	if (check_perm("timerfd_create")) { return ((sys_timerfd_create_type)laid_sc_table[__NR_timerfd_create])(clockid,flags); }
	else { return EINVAL;  }
}

SUSP(sys_eventfd,unsigned int count)
asmlinkage long susp_sys_eventfd(unsigned int count) {
	if (check_perm("eventfd")) { return ((sys_eventfd_type)laid_sc_table[__NR_eventfd])(count); }
	else { return EINVAL;  }
}

SUSP(sys_eventfd2,unsigned int count, int flags)
asmlinkage long susp_sys_eventfd2(unsigned int count, int flags) {
	if (check_perm("eventfd2")) { return ((sys_eventfd2_type)laid_sc_table[__NR_eventfd2])(count,flags); }
	else { return EINVAL;  }
}

SUSP(sys_fanotify_init,unsigned int flags, unsigned int event_f_flags)
asmlinkage long susp_sys_fanotify_init(unsigned int flags, unsigned int event_f_flags) {
	if (check_perm("fanotify_init")) { return ((sys_fanotify_init_type)laid_sc_table[__NR_fanotify_init])(flags,event_f_flags); }
	else { return EINVAL;  }
}

SUSP(sys_fanotify_mark,int fanotify_fd, unsigned int flags, u64 mask, int fd, const char __user *pathname)
asmlinkage long susp_sys_fanotify_mark(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char __user *pathname) {
	if (check_perm("fanotify_mark")) { return ((sys_fanotify_mark_type)laid_sc_table[__NR_fanotify_mark])(fanotify_fd,flags,mask,fd,pathname); }
	else { return EINVAL;  }
}

SUSP(sys_syncfs,int fd)
asmlinkage long susp_sys_syncfs(int fd) {
	if (check_perm("syncfs")) { return ((sys_syncfs_type)laid_sc_table[__NR_syncfs])(fd); }
	else { return EINVAL;  }
}

SUSP(sys_perf_event_open, struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags)
asmlinkage long susp_sys_perf_event_open( struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
	if (check_perm("perf_event_open")) { return ((sys_perf_event_open_type)laid_sc_table[__NR_perf_event_open])(attr_uptr,pid,cpu,group_fd,flags); }
	else { return EINVAL;  }
}

SUSP(sys_name_to_handle_at,int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag)
asmlinkage long susp_sys_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag) {
	if (check_perm("name_to_handle_at")) { return ((sys_name_to_handle_at_type)laid_sc_table[__NR_name_to_handle_at])(dfd,name,handle,mnt_id,flag); }
	else { return EINVAL;  }
}

SUSP(sys_setns,int fd, int nstype)
asmlinkage long susp_sys_setns(int fd, int nstype) {
	if (check_perm("setns")) { return ((sys_setns_type)laid_sc_table[__NR_setns])(fd,nstype); }
	else { return EINVAL;  }
}

SUSP(sys_kcmp,pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2)
asmlinkage long susp_sys_kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2) {
	if (check_perm("kcmp")) { return ((sys_kcmp_type)laid_sc_table[__NR_kcmp])(pid1,pid2,type,idx1,idx2); }
	else { return EINVAL;  }
}

SUSP(sys_finit_module,int fd, const char __user *uargs, int flags)
asmlinkage long susp_sys_finit_module(int fd, const char __user *uargs, int flags) {
	if (check_perm("finit_module")) { return ((sys_finit_module_type)laid_sc_table[__NR_finit_module])(fd,uargs,flags); }
	else { return EINVAL;  }
}

