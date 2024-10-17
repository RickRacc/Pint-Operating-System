#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

struct open_file
{
  struct file *file_struct; // Pointer to the file object.
  int fd_num;               // File descriptor.
  struct thread *owner;     // Owner of the file (process/thread).
  struct list_elem elem;    // List element for tracking in a list.
};

/* list of all the files open by the user process
   through syscalls*/
static struct list open_files;
static struct lock filesys_lock;

// !!NO STDERROR?
// SUPPOSED TO BE 2 or 3?
static int next_fd = 2; // 0, 1, and 2 for stdin, stdout

static uint32_t *esp;

static void syscall_handler (struct intr_frame *);

static void check_stack_pointer_validity (int num_args);
static void halt (void);
static void exit (int status);
static pid_t exec (const char *cmd_line);
static int write (int fd, const void *buffer, unsigned size);

// not sure why this is saying syntax_error
static struct open_file *add_open_file (struct file *file_struct,
                                        struct thread *owner);
static struct open_file *get_open_file (int fd_num);
static void remove_open_file (int fd_num);

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
  list_init (&open_files);
}

// Yiming driving
static void check_stack_pointer_validity (int num_args)
{
  // check if the arguments passed to the syscall are at valid user addresses
  for (int i = 0; i < num_args; i++)
    {
      if (!is_valid_user_pointer (esp + i + 1))
        {
          exit (EXIT_ERROR);
        }
    }
}

// Yiming driving
static void syscall_handler (struct intr_frame *f UNUSED)
{
  esp = f->esp;

  // check if stack pointer is valid and pointing to the syscall number
  if (!is_valid_user_pointer (esp))
    {
      exit (EXIT_ERROR);
    }

  int syscall_num = *esp;
  switch (syscall_num)
    {
      // add all the cases here
      case SYS_HALT:
        halt ();
        break;
      case SYS_EXIT:
        check_stack_pointer_validity (1);
        exit (*(esp + 1));
        break;
      case SYS_EXEC:
        check_stack_pointer_validity (1);
        f->eax = exec (*(esp + 1));
        break;
      case SYS_WAIT:
        check_stack_pointer_validity (1);
        f->eax = wait (*(esp + 1));
        break;
      // Not implemented yet
      case SYS_CREATE:
        check_stack_pointer_validity (2);
        f->eax = create (*(esp + 1), *(esp + 2));
        break;
      
      case SYS_WRITE:
        check_stack_pointer_validity (3);
        f->eax = write (*(esp + 1), *(esp + 2), *(esp + 3));
        break;

      default:
        break;
    }
}

// Annabel driving
void halt (void) { shutdown_power_off (); }

void exit (int status)
{
  struct thread *current_thread = thread_current ();
  current_thread->exit_status = status;
  thread_exit ();
}

pid_t exec (const char *cmd_line)
{
  struct thread *current_thread = thread_current ();
  tid_t return_tid = process_execute (cmd_line);
  lock_acquire (&current_thread->lock);
  while (current_thread->exec_status == EXEC_INIT)
    {
      cond_wait (&current_thread->condition, &current_thread->lock);
    }
  if (current_thread->exec_status == EXEC_ERROR)
    {
      return_tid = -1;
    }
  lock_release (&current_thread->lock);
  return return_tid;
}

int wait (pid_t pid) { return process_wait (pid); }

static int write (int fd, const void *buffer, unsigned size)
{
  if (!is_valid_user_pointer (buffer))
    {
      exit (-1);
    }

  lock_acquire (&filesys_lock);

  int bytes_written = 0;

  if (fd == STDOUT_FILENO)
    {                                  // fd == 1
      const unsigned CHUNK_SIZE = 256; // chunk size

      // Split large buffers into chunks to prevent interleaving.
      while (size > 0)
        {
          unsigned chunk = size < CHUNK_SIZE ? size : CHUNK_SIZE;
          putbuf ((const char *) buffer + bytes_written, chunk);
          bytes_written += chunk;
          size -= chunk;
        }
    }
  else
    {
      struct open_file *of = get_open_file (fd);
      if (of == NULL)
        {
          bytes_written = -1; // Return -1 if file descriptor is invalid.
        }
      else
        {
          bytes_written = file_write (of->file_struct, buffer, size);
        }
    }

  lock_release (&filesys_lock);
  return bytes_written;
}

/* Adds a new file to the open files list */
// helpful for sys_open
static struct open_file *add_open_file (struct file *file_struct,
                                        struct thread *owner)
{
  struct open_file *new_open_file = malloc (sizeof (struct open_file));
  if (new_open_file == NULL)
    return NULL;

  new_open_file->file_struct = file_struct;
  new_open_file->fd_num = next_fd++;
  new_open_file->owner = owner;

  // Add to the open_files list
  list_push_back (&open_files, &new_open_file->elem);
  return new_open_file;
}

/* Gets an open file based on its file descriptor*/
static struct open_file *get_open_file (int fd_num)
{
  struct list_elem *e;
  for (e = list_begin (&open_files); e != list_end (&open_files);
       e = list_next (e))
    {
      struct open_file *open_file = list_entry (e, struct open_file, elem);
      if (open_file->fd_num == fd_num)
        {
          return open_file; // Return the matching open_file.
        }
    }
  return NULL; // Return NULL if no matching fd is found.
}

/* Removes an open file from the list and cleans up. */
static void remove_open_file (int fd_num)
{
  struct list_elem *e;
  for (e = list_begin (&open_files); e != list_end (&open_files);
       e = list_next (e))
    {
      struct open_file *open_file = list_entry (e, struct open_file, elem);
      if (open_file->fd_num == fd_num)
        {
          list_remove (e); // Remove from the open_files list.
          file_close (open_file->file_struct); // Close the file.
          free (open_file);                    // Free the open_file struct.
          return;
        }
    }
}
