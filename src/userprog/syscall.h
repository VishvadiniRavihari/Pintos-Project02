#include "threads/thread.h"
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

struct file_descriptor {
    int fd;
    struct file *file;
    struct list_elem elem;
};

#endif /* userprog/syscall.h */
