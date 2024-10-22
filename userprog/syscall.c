#include <user/syscall.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"


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

// fd starts at 2 because 0 and 1 are reserved for stdin and stdout
// no stderr in pintos
static int next_fd = 2; 

static uint32_t *esp;

static void syscall_handler (struct intr_frame *);

//static void check_stack_pointer_validity (int num_args);

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
// static void check_stack_pointer_validity (int num_args)
// {
//   // check if the arguments passed to the syscall are at valid user addresses
//   for (int i = 0; i < num_args; i++)
//     {
//       if (!is_valid_user_pointer (esp + i + 1))
//         {
//           // printf("invalid stack pointer\n");
//           exit (EXIT_ERROR);
//         }
//     }
// }

// Yiming driving
static void syscall_handler (struct intr_frame *f UNUSED)
{
  // printf("syscall_handler\n");
  esp = f->esp;

  // check if stack pointer is valid and pointing to the syscall number
  if (!is_valid_user_pointer(esp) || !is_valid_user_pointer(esp + 1) ||
      !is_valid_user_pointer(esp + 2) || !is_valid_user_pointer(esp + 3)) {
    exit (-1);
  }


  int syscall_num = *esp;
  // printf("syscall_num: %d\n", syscall_num);
  switch (syscall_num)
    {
      // add all the cases here
      case SYS_HALT:
        halt ();
        break;
      case SYS_EXIT:
        //check_stack_pointer_validity (1);
        exit (*(esp + 1));
        break;
      case SYS_EXEC:
        //check_stack_pointer_validity (1);
        f->eax = exec ((char *) *(esp + 1));
        break;
      case SYS_WAIT:
        //check_stack_pointer_validity (1);
        f->eax = wait (*(esp + 1));
        break;
      // Not implemented yet
      case SYS_CREATE:
        //check_stack_pointer_validity (2);
        f->eax = create ((char *) *(esp + 1), *(esp + 2));
        break;
      case SYS_REMOVE:
        //check_stack_pointer_validity (1);
        f->eax = remove ((char *) *(esp + 1));
        break;
      case SYS_OPEN:
        //check_stack_pointer_validity (1);
        f->eax = open ((char *) *(esp + 1));
        break;
      case SYS_FILESIZE:
        //check_stack_pointer_validity (1);
        f->eax = filesize (*(esp + 1));
        break;

      case SYS_READ:
        //check_stack_pointer_validity (3);
        f->eax = read (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
        break;
        
      case SYS_WRITE:
        //check_stack_pointer_validity (3);
        f->eax = write (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
        break;

      case SYS_SEEK:
        //check_stack_pointer_validity (2);
        seek (*(esp + 1), *(esp + 2));
        break;

      case SYS_TELL:
        //check_stack_pointer_validity (1);
        f->eax = tell (*(esp + 1));
        break;

      case SYS_CLOSE:
        //check_stack_pointer_validity (1);
        close(*(esp + 1));
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
  printf("%s: exit(%d)\n", current_thread->name, status);
  // Exit status is now saved in this thread, if the parent process that is waiting
  // it can collect the exit status
  sema_up(&current_thread->wait);
  thread_exit ();
}

pid_t exec (const char *cmd_line)
{
  struct thread *current_thread;
  tid_t return_tid;

  
  if (!is_valid_user_pointer(cmd_line)) {
    exit(EXIT_ERROR);  
  }

  // check if the command line string extends to an invalid address
  char *c = cmd_line;
  while (*c != '\0')
    {
      c++;
      if (!is_valid_user_pointer (c))
        {
          exit(EXIT_ERROR);
        }
    }
  
  // for (const char *ptr = cmd_line; *ptr != '\0'; ptr++) {
  //   if (!is_valid_user_pointer(ptr)) {
  //     exit(EXIT_ERROR);  // Terminate if any part of the string is invalid
  //   }
  // }

  
  current_thread = thread_current ();
  // Must wait for the thread to be created and loaded
  return_tid = process_execute (cmd_line);
  if (return_tid == TID_ERROR) {
    return -1;
  }

  sema_down(&current_thread->exec);

  if (current_thread->exec_status == EXEC_ERROR){
    return_tid = -1;
  }
  return return_tid;
}

int wait (pid_t pid) { return process_wait (pid); }

// Yiming driving
bool create (const char *file, unsigned initial_size)
{
  bool success;
  if (!is_valid_user_pointer(file)) {
    exit(EXIT_ERROR);
  }

  lock_acquire (&filesys_lock);
  success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return success;
}

// Yiming driving
bool remove (const char *file)
{
  bool success;
  if (!is_valid_user_pointer (file)) {
    exit (EXEC_ERROR);
  }
  lock_acquire (&filesys_lock);
  success = filesys_remove (file);
  lock_release (&filesys_lock);
  return success;
}

// Yiming driving
int open (const char *file)
{
  struct file *file_struct;
  if (!is_valid_user_pointer (file)) {
    exit (EXEC_ERROR);
  }

  lock_acquire (&filesys_lock);
  file_struct = filesys_open (file);
  // If file opening fails, return -1
  if (file_struct == NULL)
    {
      lock_release (&filesys_lock);
      return -1;
    }
  
  // else, add the file to the list of open files
  struct open_file *new_open_file = add_open_file (file_struct, thread_current ());
  if (new_open_file == NULL)
    {
      // if adding the file to the list fails, close the file and return -1
      file_close (file_struct);
      lock_release (&filesys_lock);
      return -1;
    }
  
  lock_release (&filesys_lock);
  return new_open_file->fd_num;
}

// RAKESH DRIVING
int filesize (int fd) {
  struct open_file *f;
  int size = -1;

  lock_acquire (&filesys_lock);

  f = get_open_file(fd);
  if (f != NULL) {
    size = file_length(f->file_struct);
  }

  lock_release (&filesys_lock);
  return size;
}

// RAKESH DRIVING
int read (int fd, void *buffer, unsigned size) {
  

  lock_acquire(&filesys_lock);
  // read from the keyboard if standard input
  if (fd == STDIN_FILENO) {
    unsigned i;
    // read a character at a time
    for (i = 0; i < size; i++) {
      *((uint8_t *)buffer + i) = input_getc();
    }
    lock_release(&filesys_lock);
    return size;  
  }

  if (!is_valid_user_pointer(buffer)) {
    exit(EXIT_ERROR);
  }

  int bytes_read = -1;
  struct open_file *of = get_open_file(fd);
  if (of) {
    // read from the file
    bytes_read = file_read(of->file_struct, buffer, size);
  }
  lock_release(&filesys_lock);
  return bytes_read;
}

// RAKESH DRIVING
int write (int fd, const void *buffer, unsigned size)
{
  if (!is_valid_user_pointer(buffer)) {
    exit(EXIT_ERROR);
  }

  int bytes_written = 0;

  lock_acquire (&filesys_lock);
  if (fd == STDOUT_FILENO)
    {                                  // fd == 1
      const unsigned CHUNK = 256; // chunk size

      // Split large buffers into chunks to prevent interleaving.
      while (size > 0)
        {
          unsigned chunk = size < CHUNK ? size : CHUNK;
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

// Annabel driving
void seek(int fd, unsigned position) {
  struct open_file *of = get_open_file (fd);
  if (of) {
    file_seek (of->file_struct, position);
  }
}

unsigned tell (int fd) {
  struct open_file *of = get_open_file (fd);
  if (of == NULL) {
    exit(EXIT_ERROR);
  }
  return file_tell(of->file_struct);
}

// RAKESH DRIVING
void close (int fd) {
  lock_acquire (&filesys_lock);
  remove_open_file(fd);
  lock_release (&filesys_lock);
}


// RAKESH DRIVING
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

// RAKESH DRIVING
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

// RAKESH DRIVING
/* Removes an open file from the list and cleans up. */
static void remove_open_file (int fd_num)
{
  struct list_elem *e;
  struct thread *current_thread = thread_current();
  for (e = list_begin (&open_files); e != list_end (&open_files);
       e = list_next (e))
    {
      struct open_file *open_file = list_entry (e, struct open_file, elem);
      if (open_file->fd_num == fd_num && open_file->owner == current_thread)
        {
          list_remove (e); // Remove from the open_files list.
          file_close (open_file->file_struct); // Close the file.
          free (open_file);                    // Free the open_file struct.
          return;
        }
    }
}
