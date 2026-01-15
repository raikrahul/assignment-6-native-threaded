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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
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

/*
 * Signal handler for SIGINT (Ctrl+C) and SIGTERM (kill)
 * AXIOM: Signal handler must be async-signal-safe
 * - Only uses: write to volatile variable
 * - Does NOT: malloc, printf, syslog (not safe)
 */
void signal_handler(int sig) {
  (void)sig; /* Suppress unused warning */
  shutdown_requested = 1;
}

int main(int argc, char *argv[]) {
  int daemon_mode = 0;
  int client_fd = -1;
  struct sockaddr_in server_addr, client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  char client_ip[INET_ADDRSTRLEN]; /* 16 bytes: "255.255.255.255\0" */

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
    chdir("/");
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

  /* ================================================================
   * MAIN LOOP: Accept connections until shutdown
   * ================================================================
   * AXIOM: accept() blocks until client connects
   * - Returns new fd for client communication
   * - client_addr is filled with client IP/port
   */
  while (!shutdown_requested) {

    client_fd =
        accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd == -1) {
      if (errno == EINTR && shutdown_requested) {
        break; /* Signal received, exit loop */
      }
      syslog(LOG_ERR, "accept() failed: %s", strerror(errno));
      continue;
    }

    /* Convert binary IP to string for logging */
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    syslog(LOG_INFO, "Accepted connection from %s", client_ip);

    /* ============================================================
     * TODO BLOCK 7: RECEIVE DATA & WRITE TO FILE
     * ============================================================
     * AXIOM: recv(client_fd, buffer, size, flags)
     * - Returns bytes received (0 = client closed, -1 = error)
     * - Buffer until '\n' found
     * - Append to /var/tmp/aesdsocketdata
     *
     * REAL DATA EXAMPLE:
     * - Client sends: "Hello\nWorld\n"
     * - recv() might return: "Hell" (4 bytes)
     * - recv() might return: "o\nWor" (5 bytes) <- '\n' found at index 1
     * - Write "Hello\n" to file
     * - Buffer "Wor" for next iteration
     * - recv() might return: "ld\n" (3 bytes) <- '\n' found at index 2
     * - Write "World\n" to file
     *
     * TRAP: Must handle partial receives
     * TRAP: realloc() if buffer too small
     *
     * YOUR CODE HERE:
     */
    char *recv_buffer = malloc(BUFFER_SIZE);
    if (!recv_buffer) {
      syslog(LOG_ERR, "malloc() failed");
      close(client_fd);
      continue;
    }

    size_t buffer_size = BUFFER_SIZE;
    size_t total_received = 0;
    ssize_t bytes_received;

    while ((bytes_received = recv(client_fd, recv_buffer + total_received,
                                  buffer_size - total_received - 1, 0)) > 0) {
      total_received += bytes_received;
      recv_buffer[total_received] = '\0';

      /* Check for newline - packet complete */
      char *newline_pos;
      while ((newline_pos = strchr(recv_buffer, '\n')) != NULL) {
        size_t packet_len = newline_pos - recv_buffer + 1; /* Include '\n' */

        /* Write packet to file */
        int file_fd = open(DATA_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (file_fd == -1) {
          syslog(LOG_ERR, "open() failed: %s", strerror(errno));
        } else {
          write(file_fd, recv_buffer, packet_len);
          close(file_fd);
        }

        /* ========================================================
         * TODO BLOCK 8: SEND FILE CONTENTS BACK TO CLIENT
         * ========================================================
         * AXIOM: Cannot fit entire file in RAM (constraint from assignment)
         * - Must read in chunks and send
         * - open(DATA_FILE, O_RDONLY)
         * - Loop: read() -> send()
         *
         * REAL DATA EXAMPLE:
         * - File contains: "Hello\nWorld\n" (12 bytes)
         * - read() returns 12 bytes
         * - send(client_fd, buffer, 12, 0) sends all 12 bytes
         *
         * YOUR CODE HERE:
         */
        file_fd = open(DATA_FILE, O_RDONLY);
        if (file_fd != -1) {
          char send_buffer[BUFFER_SIZE];
          ssize_t bytes_read;
          while ((bytes_read =
                      read(file_fd, send_buffer, sizeof(send_buffer))) > 0) {
            send(client_fd, send_buffer, bytes_read, 0);
          }
          close(file_fd);
        }

        /* Shift remaining data to start of buffer */
        size_t remaining = total_received - packet_len;
        memmove(recv_buffer, newline_pos + 1, remaining);
        total_received = remaining;
        recv_buffer[total_received] = '\0';
      }

      /* Resize buffer if needed */
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
    syslog(LOG_INFO, "Closed connection from %s", client_ip);
  }

  /* ================================================================
   * CLEANUP: Signal received, graceful shutdown
   * ================================================================
   */
  syslog(LOG_INFO, "Caught signal, exiting");
  close(server_fd);
  remove(DATA_FILE);
  closelog();

  return 0;
}
