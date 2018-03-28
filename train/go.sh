stap -e 'probe nd_syscall.* { println(execname(), " ", pn()) }' | perl train.pl
