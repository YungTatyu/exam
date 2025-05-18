#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct Client {
  int id;
  int fd;
  char *buf;
};

typedef struct Client Client;

int maxfd = 0;
int listen_socket = 0;
int cur_id = 0;
int client_index = 1;
Client clients[10000];

int extract_message(char **buf, char **msg) {
  char *newbuf;
  int i;

  *msg = 0;
  if (*buf == 0)
    return (0);
  i = 0;
  while ((*buf)[i]) {
    if ((*buf)[i] == '\n') {
      newbuf = calloc(1, sizeof(*newbuf) * (strlen(*buf + i + 1) + 1));
      if (newbuf == 0)
        return (-1);
      strcpy(newbuf, *buf + i + 1);
      *msg = *buf;
      (*msg)[i + 1] = 0;
      *buf = newbuf;
      return (1);
    }
    i++;
  }
  return (0);
}

char *str_join(char *buf, char *add) {
  char *newbuf;
  int len;

  if (buf == 0)
    len = 0;
  else
    len = strlen(buf);
  newbuf = malloc(sizeof(*newbuf) * (len + strlen(add) + 1));
  if (newbuf == 0)
    return (0);
  newbuf[0] = 0;
  if (buf != 0)
    strcat(newbuf, buf);
  free(buf);
  strcat(newbuf, add);
  return (newbuf);
}

void err_exit(const char *err) {
  write(2, err, strlen(err));
  perror(NULL);
  exit(1);
}

Client *find_client(int fd) {
  for (int i = 0; i < client_index; ++i) {
    if (clients[i].fd == fd) {
      return &clients[i];
    }
  }
  return NULL;
}

void new_client(int fd) {
  clients[client_index].fd = fd;
  clients[client_index].id = cur_id;
  clients[client_index].buf = NULL;
  ++client_index;
  ++cur_id;

  maxfd = fd > maxfd ? fd : maxfd;
}

void delete_client(int fd) {
  Client *c = find_client(fd);
  if (c == NULL) {
    return;
  }
  c->fd = -1;
  free(c->buf);
  c->buf = NULL;
  close(fd);
}

void update_maxfd() {
  int max = -1;
  for (int i = 0; i < client_index; i++) {
    if (clients[i].fd > max) {
      max = clients[i].fd;
    }
  }
  maxfd = max;
}

void add_buffer(char *buff, int except) {
  for (int i = 0; i < client_index; ++i) {
    int fd = clients[i].fd;
    if (fd == except || fd == listen_socket || fd == -1) {
      continue;
    }
    clients[i].buf = str_join(clients[i].buf, buff);
    if (clients[i].buf == NULL) {
      err_exit("Fatal error\n");
    }
  }
}

void accept_client() {
  int client = accept(listen_socket, NULL, NULL);
  // printf("accepting client: %d\n", client);
  if (client < 0) {
    err_exit("Fatal error\n");
  }
  new_client(client);
  char buff[100] = {0};
  sprintf(buff, "server: client %d just arrived\n", cur_id - 1);
  add_buffer(buff, client);
}

void send_message(int fd) {
  // printf("sending message: %d\n", fd);
  char *buff = NULL;
  Client *c = find_client(fd);
  if (c == NULL) {
    return;
  }
  int re = extract_message(&c->buf, &buff);
  if (re == -1) {
    err_exit("Fatal error\n");
  }
  if (re == 0) {
    return;
  }
  // printf("sending: %s\n", buff);
  // 本当はnon blockingで送信したほうがいい
  // ssize_t sent = send(fd, buff, strlen(buff), MSG_DONTWAIT | MSG_NOSIGNAL);
  ssize_t sent = send(fd, buff, strlen(buff), 0);
  free(buff);
  // errの場合どうする？？？
  if (sent < 0) {
    err_exit("Fatal error\n");
  }
  // printf("%zu bytes sent\n", sent);
  // if (c->buf[0] == '\0') {
  //   free(c->buf);
  //   c->buf = NULL;
  // }
}

void recv_message(int fd) {
  // printf("recving message: %d\n", fd);
  char buff[2000] = {0};
  char client_info[100] = {0};
  Client *c = find_client(fd);
  if (c == NULL) {
    return;
  }
  sprintf(client_info, "client %d: ", c->id);
  // sprintf(buff, client_info);
  // ssize_t re = recv(fd, &buff[strlen(buff)], 1024, MSG_DONTWAIT |
  // MSG_NOSIGNAL);
  // 本当はnon blockingで受信したほうがいい
  ssize_t re = recv(fd, &buff[strlen(buff)], 1024, 0);
  if (re < 0) {
    err_exit("Fatal error\n");
  }
  char *formatted = NULL;
  if (re == 0) {
    bzero(buff, sizeof(buff));
    sprintf(buff, "server: client %d just left\n", c->id);
    formatted = buff;
    delete_client(fd);
    update_maxfd();
  } else if (strstr(buff, "\n") == NULL) {
    formatted = str_join(formatted, client_info);
    if (formatted == NULL) {
      err_exit("Fatal error\n");
    }
    formatted = str_join(formatted, buff);
    if (formatted == NULL) {
      err_exit("Fatal error\n");
    }
  } else {
    char *start = buff;
    char *nl;
    while ((nl = strstr(start, "\n"))) {
      formatted = str_join(formatted, client_info);
      if (formatted == NULL) {
        err_exit("Fatal error\n");
      }
      formatted = str_join(formatted, start);
      *nl = '\0';
      if (formatted == NULL) {
        err_exit("Fatal error\n");
      }
      start = nl + 1;
    }
  }
  add_buffer(formatted, c->fd);
}

void register_event(fd_set *read, fd_set *write) {
  FD_ZERO(read);
  FD_ZERO(write);
  for (int i = 0; i < client_index; ++i) {
    if (clients[i].fd == -1) {
      continue;
    }
    // printf("register fd %d\n", clients[i].fd);
    FD_SET(clients[i].fd, read);
    if (clients[i].buf != NULL) {
      FD_SET(clients[i].fd, write);
    }
  }
}

void event_loop(int listen_socket) {
  while (1) {
    fd_set read;
    fd_set write;
    register_event(&read, &write);
    int re = select(maxfd + 1, &read, &write, NULL, NULL);
    // printf("events happend: %d\n", re);
    if (re < 0) {
      err_exit("Fatal error\n");
    }
    for (int i = 0; i < client_index; ++i) {
      int fd = clients[i].fd;
      // printf("%d socket\n", fd);
      if (fd == -1) {
        continue;
      }
      if (FD_ISSET(fd, &write)) {
        // printf("%d socket: write\n", fd);
        send_message(fd);
      }
      if (FD_ISSET(fd, &read)) {
        // printf("%d socket: read\n", fd);
        if (fd == listen_socket) {
          accept_client();
        } else {
          recv_message(fd);
        }
      }
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    err_exit("Wrong number of arguments\n");
  }
  struct sockaddr_in servaddr;

  // socket create and verification
  listen_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_socket == -1) {
    err_exit("Fatal error\n");
  }
  bzero(&servaddr, sizeof(servaddr));

  // assign IP, PORT
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(2130706433); // 127.0.0.1
  servaddr.sin_port = htons(atoi(argv[1]));

  // Binding newly created socket to given IP and verification
  if ((bind(listen_socket, (const struct sockaddr *)&servaddr,
            sizeof(servaddr))) != 0) {
    err_exit("Fatal error\n");
  }
  if (listen(listen_socket, 10) != 0) {
    err_exit("Fatal error\n");
  }
  clients[0].fd = listen_socket;
  clients[0].id = -1;
  clients[0].buf = NULL;
  maxfd = listen_socket;
  event_loop(listen_socket);
  return 1;
}
