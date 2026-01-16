/*
 * aesdsocket.c - Assignment 5 Part 1: Native Socket Server
 *
 * AXIOMS:
 * - PORT = 9000 (decimal) = 0x2328 (hex, big-endian) = 0x2823 (little-endian on
 * x86)
 * - htons(9000) converts 0x2823 -> 0x2328 for network transmission
 * - BACKLOG = 10 (max pending connections in listen queue)
 * - DATA_FILE = "/var/tmp/aesdsocketdata"
 * - BUFFER_SIZE = 1024 (initial recv buffer, will realloc if needed)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define PORT 9000
#define BACKLOG 10
#define DATA_FILE "/var/tmp/aesdsocketdata"
#define BUFFER_SIZE 1024

/*
 * AXIOM: volatile sig_atomic_t is the ONLY safe type for signal handlers
 * - sizeof(sig_atomic_t) = 4 bytes on most platforms
 * - volatile prevents compiler from caching in register
 * - Write: signal handler sets to 1
 * - Read: main loop checks != 0
 */
volatile sig_atomic_t shutdown_requested = 0;

/* Global socket fd for cleanup in signal handler */
int server_fd = -1;
pthread_mutex_t file_mutex;
/*
 * Signal handler for SIGINT (Ctrl+C) and SIGTERM (kill)
 * AXIOM: Signal handler must be async-signal-safe
 * - Sets shutdown flag and closes server socket to interrupt accept()
 */
void signal_handler(int sig) {
  (void)sig; /* Suppress unused warning */
  shutdown_requested = 1;
  /* Close server socket to interrupt accept() call */
  if (server_fd != -1) {
    close(server_fd);
    server_fd = -1;
  }
}
struct slist_data_s {
  SLIST_ENTRY(slist_data_s) entries;
  int client_fd;
  pthread_t thread;
  int thread_complete;
};

void *thread_function(void *thread_param);
void *timer_thread(void *timer_param);

int main(int argc, char *argv[]) {
  int daemon_mode = 0;
  int client_fd = -1;
  struct sockaddr_in server_addr, client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  pthread_mutex_init(&file_mutex, NULL);
  char client_ip[INET_ADDRSTRLEN]; /* 16 bytes: "255.255.255.255\0" */

  SLIST_HEAD(slistthread, slist_data_s) head;
  SLIST_INIT(&head);
  /*
   * AXIOM: argc = argument count, argv[0] = program name
   * - argc=1: just "./aesdsocket"
   * - argc=2: "./aesdsocket -d"
   */
  if (argc == 2 && strcmp(argv[1], "-d") == 0) {
    daemon_mode = 1;
  }

  /* Open syslog with: facility=LOG_USER, options=LOG_PID|LOG_PERROR */
  openlog("aesdsocket", LOG_PID | LOG_PERROR, LOG_USER);

  /* Clean up any existing data file to ensure fresh start */
  remove(DATA_FILE);

  /* ================================================================
   * TODO BLOCK 1: SOCKET CREATION
   * ================================================================
   * AXIOM: socket(domain, type, protocol)
   * - domain = AF_INET = 2 (IPv4)
   * - type = SOCK_STREAM = 1 (TCP)
   * - protocol = 0 (auto-select based on type)
   *
   * RETURN: file descriptor (int >= 0) on success, -1 on failure
   * TRAP: Must check return value
   *
   * YOUR CODE HERE:
   */
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1) {
    syslog(LOG_ERR, "socket() failed: %s", strerror(errno));
    return -1;
  }

  /* ================================================================
   * TODO BLOCK 2: SO_REUSEADDR
   * ================================================================
   * AXIOM: After close(), kernel holds port in TIME_WAIT for ~60 seconds
   * - Without SO_REUSEADDR: bind() fails with "Address already in use"
   * - optval = 1 (enable)
   * - setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
   *
   * YOUR CODE HERE:
   */
  int optval = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval,
                 sizeof(optval)) == -1) {
    syslog(LOG_ERR, "setsockopt() failed: %s", strerror(errno));
    close(server_fd);
    return -1;
  }

  /* ================================================================
   * TODO BLOCK 3: BIND
   * ================================================================
   * AXIOM: struct sockaddr_in layout (16 bytes total):
   * - sin_family: 2 bytes (AF_INET = 2)
   * - sin_port: 2 bytes (network byte order, htons(9000) = 0x2328)
   * - sin_addr.s_addr: 4 bytes (INADDR_ANY = 0x00000000 = all interfaces)
   * - padding: 8 bytes
   *
   * memset clears struct to 0 before filling fields
   *
   * YOUR CODE HERE:
   */
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(PORT);
  server_addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) ==
      -1) {
    syslog(LOG_ERR, "bind() failed: %s", strerror(errno));
    close(server_fd);
    return -1;
  }

  /* ================================================================
   * TODO BLOCK 4: DAEMON MODE (fork after bind succeeds)
   * ================================================================
   * AXIOM: fork() returns:
   * - < 0: error
   * - = 0: child process
   * - > 0: parent process (value = child PID)
   *
   * Parent exits, child continues.
   * setsid() creates new session, child becomes session leader.
   *
   * YOUR CODE HERE (only if daemon_mode == 1):
   */
  if (daemon_mode) {
    pid_t pid = fork();
    if (pid < 0) {
      syslog(LOG_ERR, "fork() failed: %s", strerror(errno));
      close(server_fd);
      return -1;
    }
    if (pid > 0) {
      /* Parent exits cleanly */
      exit(0);
    }
    /* Child continues */
    setsid();
    if (chdir("/") == -1) {
      syslog(LOG_ERR, "chdir() failed: %s", strerror(errno));
      exit(1);
    }
    /* Redirect stdin/stdout/stderr to /dev/null */
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd != -1) {
      dup2(null_fd, STDIN_FILENO);  /* fd 0 → /dev/null */
      dup2(null_fd, STDOUT_FILENO); /* fd 1 → /dev/null */
      dup2(null_fd, STDERR_FILENO); /* fd 2 → /dev/null */
      if (null_fd > 2)
        close(null_fd);
    }
  }

  /* ================================================================
   * TODO BLOCK 5: LISTEN
   * ================================================================
   * AXIOM: listen(fd, backlog)
   * - backlog = 10 (max pending connections)
   * - Marks socket as passive (waiting for connections)
   *
   * YOUR CODE HERE:
   */
  if (listen(server_fd, BACKLOG) == -1) {
    syslog(LOG_ERR, "listen() failed: %s", strerror(errno));
    close(server_fd);
    return -1;
  }

  /* ================================================================
   * TODO BLOCK 6: SIGNAL HANDLERS
   * ================================================================
   * AXIOM: struct sigaction
   * - sa_handler = pointer to handler function
   * - SA_RESTART = restart interrupted syscalls (like accept)
   *
   * YOUR CODE HERE:
   */
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Ignore SIGPIPE to prevent crashes when clients disconnect */
  signal(SIGPIPE, SIG_IGN);

  /* ================================================================
   * MAIN LOOP: Accept connections until shutdown
   * ================================================================
   * AXIOM: accept() blocks until client connects
   * - Returns new fd for client communication
   * - client_addr is filled with client IP/port
   */

  pthread_t timer_id;
  pthread_create(&timer_id, NULL, timer_thread, NULL);

  while (!shutdown_requested) {

    client_fd =
        accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd == -1) {
      if (errno == EINTR) {
        break; /* Signal received, exit loop */
      }
      if (shutdown_requested) {
        break; /* Shutdown requested, exit loop */
      }
      syslog(LOG_ERR, "accept() failed: %s", strerror(errno));
      continue;
    }

    struct slist_data_s *datap = malloc(sizeof(struct slist_data_s));
    datap->client_fd = client_fd;
    datap->thread_complete = 0;
    if (pthread_create(&datap->thread, NULL, thread_function, datap) != 0) {
      syslog(LOG_ERR, "pthread_create() failed: %s", strerror(errno));
      close(client_fd);
      free(datap);
      continue;
    }
    SLIST_INSERT_HEAD(&head, datap, entries);

    /* Convert binary IP to string for logging */
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);

    /* Cleanup finished threads (non-blocking) */
    struct slist_data_s *iter_datap = SLIST_FIRST(&head);
    while (iter_datap != NULL) {
      struct slist_data_s *next_datap = SLIST_NEXT(iter_datap, entries);
      if (iter_datap->thread_complete == 1) {
        pthread_join(iter_datap->thread, NULL);
        SLIST_REMOVE(&head, iter_datap, slist_data_s, entries);
        free(iter_datap);
      }
      iter_datap = next_datap;
    }
  }

  /* ================================================================
   * CLEANUP: Signal received, graceful shutdown
   * ================================================================
   */
  struct slist_data_s *iter_datap = SLIST_FIRST(&head);
  while (iter_datap != NULL) {
    struct slist_data_s *temp_datap = SLIST_NEXT(iter_datap, entries);
    pthread_join(iter_datap->thread, NULL);
    SLIST_REMOVE(&head, iter_datap, slist_data_s, entries);
    free(iter_datap);
    iter_datap = temp_datap;
  }

  pthread_join(timer_id, NULL);

  syslog(LOG_INFO, "Caught signal, exiting");
  if (server_fd != -1) {
    close(server_fd);
  }
  remove(DATA_FILE);
  closelog();
  pthread_mutex_destroy(&file_mutex);

  return 0;
}

void *thread_function(void *thread_param) {
  struct slist_data_s *thread_func_args = (struct slist_data_s *)thread_param;
  int client_fd = thread_func_args->client_fd;

  char *recv_buffer = malloc(BUFFER_SIZE);
  if (!recv_buffer) {
    syslog(LOG_ERR, "malloc() failed");
    close(client_fd);
    thread_func_args->thread_complete = 1;
    return NULL;
  }

  size_t buffer_size = BUFFER_SIZE;
  size_t total_received = 0;
  ssize_t bytes_received;

  while ((bytes_received = recv(client_fd, recv_buffer + total_received,
                                buffer_size - total_received - 1, 0)) > 0) {
    total_received += bytes_received;
    recv_buffer[total_received] = '\0';

    char *newline_pos;
    while ((newline_pos = strchr(recv_buffer, '\n')) != NULL) {
      size_t packet_len = newline_pos - recv_buffer + 1;

      /* CRITICAL SECTION START */
      if (pthread_mutex_lock(&file_mutex) != 0) {
        syslog(LOG_ERR, "mutex lock failed");
        // Handle error, maybe break
      }

      int file_fd = open(DATA_FILE, O_RDWR | O_CREAT | O_APPEND, 0644);
      if (file_fd == -1) {
        syslog(LOG_ERR, "open() failed: %s", strerror(errno));
      } else {
        if (write(file_fd, recv_buffer, packet_len) == -1) {
          syslog(LOG_ERR, "write() failed: %s", strerror(errno));
        }

        lseek(file_fd, 0, SEEK_SET);
        char send_buffer[BUFFER_SIZE];
        ssize_t bytes_read;
        while ((bytes_read = read(file_fd, send_buffer, sizeof(send_buffer))) >
               0) {
          send(client_fd, send_buffer, bytes_read, 0);
        }
        close(file_fd);
      }

      if (pthread_mutex_unlock(&file_mutex) != 0) {
        syslog(LOG_ERR, "mutex unlock failed");
      }
      /* CRITICAL SECTION END */

      size_t remaining = total_received - packet_len;
      memmove(recv_buffer, newline_pos + 1, remaining);
      total_received = remaining;
      recv_buffer[total_received] = '\0';
    }

    if (total_received >= buffer_size - 1) {
      buffer_size *= 2;
      char *new_buffer = realloc(recv_buffer, buffer_size);
      if (!new_buffer) {
        syslog(LOG_ERR, "realloc() failed");
        break;
      }
      recv_buffer = new_buffer;
    }
  }

  free(recv_buffer);
  close(client_fd);
  thread_func_args->thread_complete = 1;
  return NULL;
}

void *timer_thread(void *timer_param) {

  while (!shutdown_requested) {
    if (sleep(10) != 0)
      break;

    time_t now;
    struct tm *tm_info;
    char time_str[128];

    time(&now);
    tm_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "timestamp:%a, %d %b %Y %T %z\n",
             tm_info);

    if (pthread_mutex_lock(&file_mutex) != 0) {
      syslog(LOG_ERR, "mutex lock failed");
    }
    int file_fd = open(DATA_FILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (file_fd == -1) {
      syslog(LOG_ERR, "open() failed: %s", strerror(errno));
    } else {
      if (write(file_fd, time_str, strlen(time_str)) == -1) {
        syslog(LOG_ERR, "write() failed: %s", strerror(errno));
      }
      close(file_fd);
    }
    if (pthread_mutex_unlock(&file_mutex) != 0) {
      syslog(LOG_ERR, "mutex unlock failed");
    }
  }
  return NULL;
}
