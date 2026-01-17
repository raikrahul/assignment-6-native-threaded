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

volatile sig_atomic_t shutdown_requested = 0;

int server_fd = -1;
pthread_mutex_t file_mutex;

void signal_handler(int sig) {
  (void)sig;
  shutdown_requested = 1;

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

SLIST_HEAD(slistthread, slist_data_s);
struct slistthread head = SLIST_HEAD_INITIALIZER(head);

void *thread_function(void *thread_param);
void *timer_thread(void *timer_param);
void file_write(char *data, int len);
struct slist_data_s *spawn_client_thread(int client_fd,
                                         struct sockaddr_in *addr);
void cleanup_finished_threads(struct slistthread *head);
void join_all_threads(void);
int main(int argc, char *argv[]) {
  int daemon_mode = 0;
  int client_fd = -1;
  struct sockaddr_in server_addr, client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  pthread_mutex_init(&file_mutex, NULL);

  if (argc == 2 && strcmp(argv[1], "-d") == 0) {
    daemon_mode = 1;
  }

  openlog("aesdsocket", LOG_PID | LOG_PERROR, LOG_USER);

  remove(DATA_FILE);
  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1) {
    syslog(LOG_ERR, "socket() failed: %s", strerror(errno));
    return -1;
  }
  int optval = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval,
                 sizeof(optval)) == -1) {
    syslog(LOG_ERR, "setsockopt() failed: %s", strerror(errno));
    close(server_fd);
    return -1;
  }
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
  if (daemon_mode) {
    pid_t pid = fork();
    if (pid < 0) {
      syslog(LOG_ERR, "fork() failed: %s", strerror(errno));
      close(server_fd);
      return -1;
    }
    if (pid > 0) {

      exit(0);
    }

    setsid();
    if (chdir("/") == -1) {
      syslog(LOG_ERR, "chdir() failed: %s", strerror(errno));
      exit(1);
    }

    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd != -1) {
      dup2(null_fd, STDIN_FILENO);
      dup2(null_fd, STDOUT_FILENO);
      dup2(null_fd, STDERR_FILENO);
      if (null_fd > 2)
        close(null_fd);
    }
  }
  if (listen(server_fd, BACKLOG) == -1) {
    syslog(LOG_ERR, "listen() failed: %s", strerror(errno));
    close(server_fd);
    return -1;
  }
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  signal(SIGPIPE, SIG_IGN);
  pthread_t timer_id;
  pthread_create(&timer_id, NULL, timer_thread, NULL);

  while (!shutdown_requested) {

    client_fd =
        accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd == -1) {
      if (errno == EINTR) {
        break;
      }
      if (shutdown_requested) {
        break;
      }
      syslog(LOG_ERR, "accept() failed: %s", strerror(errno));
      continue;
    }

    struct slist_data_s *datap;
    if ((datap = spawn_client_thread(client_fd, &client_addr)))
      SLIST_INSERT_HEAD(&head, datap, entries);

    cleanup_finished_threads(&head);
  }

  join_all_threads();

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

      if (pthread_mutex_lock(&file_mutex) != 0) {
        syslog(LOG_ERR, "mutex lock failed");
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
    sleep(10);

    time_t now;
    struct tm *tm_info;
    char time_str[128];

    time(&now);
    tm_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "timestamp:%a, %d %b %Y %T %z\n",
             tm_info);

    file_write(time_str, strlen(time_str));
  }
  return NULL;
}

void file_write(char *data, int len) {
  pthread_mutex_lock(&file_mutex);
  int file_fd = open(DATA_FILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
  if (file_fd != -1) {
    if (write(file_fd, data, len) == -1) {
      syslog(LOG_ERR, "write() failed: %s", strerror(errno));
    }
    close(file_fd);
  }
  pthread_mutex_unlock(&file_mutex);
}

struct slist_data_s *spawn_client_thread(int client_fd,
                                         struct sockaddr_in *addr) {
  struct slist_data_s *datap = malloc(sizeof(struct slist_data_s));
  if (datap == NULL) {
    syslog(LOG_ERR, "malloc() failed: %s", strerror(errno));
    close(client_fd);
    return NULL;
  }

  datap->client_fd = client_fd;
  datap->thread_complete = 0;

  if (pthread_create(&datap->thread, NULL, thread_function, datap) != 0) {
    syslog(LOG_ERR, "pthread_create() failed: %s", strerror(errno));
    close(client_fd);
    free(datap);
    return NULL;
  }

  char client_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &addr->sin_addr, client_ip, sizeof(client_ip));
  syslog(LOG_INFO, "Accepted connection from %s", client_ip);

  return datap;
}

void cleanup_finished_threads(struct slistthread *head) {
  struct slist_data_s *iter_datap = SLIST_FIRST(head);
  while (iter_datap != NULL) {
    struct slist_data_s *next_datap = SLIST_NEXT(iter_datap, entries);
    if (iter_datap->thread_complete == 1) {
      pthread_join(iter_datap->thread, NULL);
      SLIST_REMOVE(head, iter_datap, slist_data_s, entries);
      free(iter_datap);
    }
    iter_datap = next_datap;
  }
}

void join_all_threads(void) {
  struct slist_data_s *iter_datap = SLIST_FIRST(&head);
  while (iter_datap != NULL) {
    struct slist_data_s *temp_datap = SLIST_NEXT(iter_datap, entries);
    pthread_join(iter_datap->thread, NULL);
    SLIST_REMOVE(&head, iter_datap, slist_data_s, entries);
    free(iter_datap);
    iter_datap = temp_datap;
  }
}
