#include "userprog/syscall.h"
#include "lib/stdio.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <syscall-nr.h>

static void syscall_handler(struct intr_frame *);
static int get_user(const uint8_t *uaddr);
static int read_mem(void *adr, void *buffer, unsigned size);
struct lock file_sys_lock;

void syscall_init(void) {
    lock_init(&file_sys_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED) {
    int syscall;
    if (!read_mem(f->esp, &syscall, sizeof(syscall))) {
        exit(-1);
    }

    // printf("syscall: %d\n", syscall);

    if (syscall == SYS_OPEN) {
        const char *file;
        if (!read_mem(f->esp + 4, &file, sizeof(file))) {
            exit(-1);
        }
        f->eax = open_file(file);
    } else if (syscall == SYS_EXIT) {
        int exit_status;
        if (!read_mem(f->esp + 4, &exit_status, sizeof(exit_status))) {
            exit(-1);
        }
        exit(exit_status);
    } else if (syscall == SYS_HALT) {
        shutdown_power_off();
    } else if (syscall == SYS_WRITE) {
        int fd;
        const void *buffer;
        unsigned size;
        bool error_cond = !read_mem(f->esp + 4, &fd, sizeof(fd)) || !read_mem(f->esp + 8, &buffer, sizeof(buffer)) || !read_mem(f->esp + 12, &size, sizeof(size));
        // printf("fd: %d, buffer: %c, size: %d\n", fd, buffer, size);
        if (error_cond) {
            exit(-1);
            return;
        }
        if (fd < 0 || !is_user_vaddr(buffer) || get_user(buffer) == -1 || !is_user_vaddr(buffer + size) || get_user(buffer + size) == -1) {
            exit(-1);
        } else if (fd == 1) {
            putbuf(buffer, size);
            f->eax = size;
        } else {
            // lock_acquire(&file_sys_lock);
            // struct thread *cur = thread_current();
            // struct list_elem *e;
            // for (e = list_begin(&cur->list_file_descriptors); e != list_end(&cur->list_file_descriptors); e = list_next(e)) {
            //     struct file_descriptor *file_desc = list_entry(e, struct file_descriptor, elem);
            //     if (file_desc->fd == fd) {
            //         f->eax = file_write(file_desc->file, buffer, size);
            //         break;
            //     }
            // }
            // lock_release(&file_sys_lock);
        }
    } else {
        // printf("syscall %d\n", syscall);
    }
}

/**
 * It reads a given number of bytes from a given address in the user's memory space and stores them in
 * a given buffer
 *
 * @param adr The address of the memory we want to read
 * @param buffer the buffer to write to
 * @param size the number of bytes to read
 *
 * @return The number of bytes read.
 */
static int read_mem(void *adr, void *buffer, unsigned size) {
    unsigned val = 0;
    while (val < size && is_user_vaddr(adr + val)) {
        int byte = get_user(adr + val);
        if (byte == -1) {
            break;
        }
        *(char *)(buffer + val) = (uint8_t)byte;
        val++;
    }

    // if following boolean is false we know an error occurred
    return val == size;
}

/**
 * It opens a file and adds it to the list of file descriptors for the current thread.
 *
 * @param file The name of the file to open.
 *
 * @return The file descriptor of the file that was opened.
 */
int open_file(const char *file) {

    if (file == NULL) {
        return -1;
    }

    lock_acquire(&file_sys_lock);
    struct file *opened = filesys_open(file);
    lock_release(&file_sys_lock);

    struct thread *cur = thread_current();

    if (opened == NULL) {
        return -1;
    } else {
        cur->file_count++;
        struct file_descriptor *file_desc = malloc(sizeof(struct file_descriptor));

        file_desc->file = opened;
        file_desc->fd = cur->file_count;

        list_push_back(&cur->list_file_descriptors, &file_desc->elem);
        return cur->file_count;
    }
}

/**
 * It prints the name of the current thread and the exit code, and then exits the current thread
 *
 * @param exit_code The exit code to return to the parent process.
 */
int exit(int exit_code) {
    printf("%s: exit(%d)\n", thread_current()->name, exit_code);
    thread_exit();
}

static int
get_user(const uint8_t *uaddr) {
    int result;
    asm("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a"(result)
        : "m"(*uaddr));
    return result;
}