#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"

void syscall_init (void);
void check_file_descriptor (struct file_descriptor *fd);

#endif /* userprog/syscall.h */
