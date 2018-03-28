#define SUSP(SYS_SC,...) typedef asmlinkage long (*SYS_SC##_type) (__VA_ARGS__);

#define SUSP_INIT(SCname) laid_sc_table[__NR_##SCname] = (void *)sys_call_table[__NR_##SCname]; \
sys_call_table[__NR_##SCname] = (unsigned long *)susp_sys_##SCname;

#define SUSP_VERSA(SCname) sys_call_table[__NR_##SCname] = (unsigned long *)laid_sc_table[__NR_##SCname];

#define SUSP_WRAP_UNNAMED6(SC,t1,t2,t3,t4,t5,t6) asmlinkage long susp_sys_##SC(t1 a, t2 b, t3 c, t4 d, t5 e, t6 f) { \
if (check_perm(#SC)) return ((sys_##SC##_type)laid_sc_table[__NR_##SC])(a, b, c, d, e, f);\
            else return -1;\
}

#define SUSP_WRAP_UNNAMED5(SC,t1,t2,t3,t4,t5) asmlinkage long susp_sys_##SC(t1 a, t2 b, t3 c, t4 d, t5 e) { \
if (check_perm(#SC)) return ((sys_##SC##_type)laid_sc_table[__NR_##SC])(a, b, c, d, e);\
            else return -1;\
}

#define SUSP_WRAP_UNNAMED4(SC,t1,t2,t3,t4) asmlinkage long susp_sys_##SC(t1 a, t2 b, t3 c, t4 d) { \if (check_perm(#SC)) return ((sys_##SC##_type)laid_sc_table[__NR_##SC])(a, b, c, d);\
        else return -1;\
}

#define SUSP_WRAP_UNNAMED3(SC,t1,t2,t3) asmlinkage long susp_sys_##SC(t1 a, t2 b, t3 c) { \
if (check_perm(#SC)) return ((sys_##SC##_type)laid_sc_table[__NR_##SC])(a, b, c);\
            else return -1;\
}

#define SUSP_WRAP_UNNAMED2(SC,t1,t2) asmlinkage long susp_sys_##SC(t1 a, t2 b) { \
if (check_perm(#SC)) return ((sys_##SC##_type)laid_sc_table[__NR_##SC])(a, b);\
            else return -1;\
}

#define SUSP_WRAP_UNNAMED(SC,t1) asmlinkage long susp_sys_##SC(t1 a) { \
if (check_perm(#SC)) return ((sys_##SC##_type)laid_sc_table[__NR_##SC])(a);\
            else return -1;\
}

