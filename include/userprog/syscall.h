#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void check_file_descriptor (struct file_descriptor *fd);

#endif /* userprog/syscall.h */
