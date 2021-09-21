/**
   @file rexmpp_tcp.c
   @brief TCP connection establishment.
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#include <netdb.h>
#include <arpa/nameser.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <memory.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "rexmpp.h"
#include "rexmpp_tcp.h"
#include "rexmpp_dns.h"


void rexmpp_tcp_dns_aaaa_cb (rexmpp_t *s,
                             void *ptr,
                             rexmpp_dns_result_t *result)
{
  (void)s;
  rexmpp_tcp_conn_t *conn = ptr;
  conn->resolved_v6 = result;
  if (result != NULL) {
    conn->resolution_v6 = REXMPP_CONN_RESOLUTION_SUCCESS;
    conn->addr_cur_v6 = -1;
  } else {
    conn->resolution_v6 = REXMPP_CONN_RESOLUTION_FAILURE;
  }
}

void rexmpp_tcp_dns_a_cb (rexmpp_t *s,
                          void *ptr,
                          rexmpp_dns_result_t *result)
{
  (void)s;
  rexmpp_tcp_conn_t *conn = ptr;
  conn->resolved_v4 = result;
  if (result != NULL) {
    conn->resolution_v4 = REXMPP_CONN_RESOLUTION_SUCCESS;
    conn->addr_cur_v4 = -1;
    if (conn->resolution_v6 == REXMPP_CONN_RESOLUTION_WAITING) {
      /* Wait for 50 ms for IPv6. */
      gettimeofday(&(conn->next_connection_time), NULL);
      conn->next_connection_time.tv_usec += REXMPP_TCP_IPV6_DELAY_MS * 1000;
      if (conn->next_connection_time.tv_usec >= 1000000) {
        conn->next_connection_time.tv_usec -= 1000000;
        conn->next_connection_time.tv_sec++;
      }
    }
  } else {
    conn->resolution_v4 = REXMPP_CONN_RESOLUTION_FAILURE;
  }
}

void rexmpp_tcp_cleanup (rexmpp_tcp_conn_t *conn) {
  int i;
  for (i = 0; i < REXMPP_TCP_MAX_CONNECTION_ATTEMPTS; i++) {
    if (conn->sockets[i] != -1 && conn->sockets[i] != conn->fd) {
      close(conn->sockets[i]);
      conn->sockets[i] = -1;
    }
  }
  if (conn->resolution_v4 != REXMPP_CONN_RESOLUTION_INACTIVE) {
    conn->resolution_v4 = REXMPP_CONN_RESOLUTION_INACTIVE;
    conn->resolution_v6 = REXMPP_CONN_RESOLUTION_INACTIVE;
  }
  if (conn->resolved_v4 != NULL) {
    rexmpp_dns_result_free(conn->resolved_v4);
    conn->resolved_v4 = NULL;
  }
  if (conn->resolved_v6 != NULL) {
    rexmpp_dns_result_free(conn->resolved_v6);
    conn->resolved_v6 = NULL;
  }
}

rexmpp_tcp_conn_error_t
rexmpp_tcp_connected (rexmpp_tcp_conn_t *conn, int fd) {
  struct sockaddr sa;
  socklen_t sa_len = sizeof(sa);
  getsockname(fd, &sa, &sa_len);
  if (sa.sa_family == AF_INET) {
    conn->dns_secure = conn->resolved_v4->secure;
  } else {
    conn->dns_secure = conn->resolved_v6->secure;
  }
  conn->fd = fd;
  rexmpp_tcp_cleanup(conn);
  return REXMPP_CONN_DONE;
}

rexmpp_tcp_conn_error_t
rexmpp_tcp_conn_init (rexmpp_t *s,
                      rexmpp_tcp_conn_t *conn,
                      const char *host,
                      uint16_t port)
{
  int i;
  for (i = 0; i < REXMPP_TCP_MAX_CONNECTION_ATTEMPTS; i++) {
    conn->sockets[i] = -1;
  }
  conn->connection_attempts = 0;
  conn->port = port;
  conn->resolved_v4 = NULL;
  conn->resolved_v6 = NULL;
  conn->fd = -1;
  conn->dns_secure = 0;
  conn->next_connection_time.tv_sec = 0;
  conn->next_connection_time.tv_usec = 0;

  conn->resolution_v4 = REXMPP_CONN_RESOLUTION_INACTIVE;
  conn->resolution_v6 = REXMPP_CONN_RESOLUTION_INACTIVE;

  struct sockaddr_in addr_v4;
  int flags;
  if (inet_pton(AF_INET, host, &addr_v4)) {
    addr_v4.sin_family = AF_INET;
    addr_v4.sin_port = htons(port);
    conn->sockets[conn->connection_attempts] =
      socket(AF_INET, SOCK_STREAM, 0);
    flags = fcntl(conn->sockets[conn->connection_attempts], F_GETFL, 0);
    fcntl(conn->sockets[conn->connection_attempts], F_SETFL, flags | O_NONBLOCK);
    if (connect(conn->sockets[conn->connection_attempts],
                (struct sockaddr*)&addr_v4,
                sizeof(addr_v4))) {
      if (errno != EINPROGRESS) {
        return REXMPP_CONN_ERROR;
      }
    } else {
      return rexmpp_tcp_connected(conn,
                                  conn->sockets[conn->connection_attempts]);
    }
    conn->connection_attempts++;
    return REXMPP_CONN_IN_PROGRESS;
  }
  struct sockaddr_in addr_v6;
  if (inet_pton(AF_INET6, host, &addr_v6)) {
    addr_v6.sin_family = AF_INET6;
    addr_v6.sin_port = htons(port);
    conn->sockets[conn->connection_attempts] =
      socket(AF_INET6, SOCK_STREAM, 0);
    flags = fcntl(conn->sockets[conn->connection_attempts], F_GETFL, 0);
    fcntl(conn->sockets[conn->connection_attempts], F_SETFL, flags | O_NONBLOCK);
    if (connect(conn->sockets[conn->connection_attempts],
                (struct sockaddr*)&addr_v6,
                sizeof(addr_v6))) {
      if (errno != EINPROGRESS) {
        return REXMPP_CONN_ERROR;
      }
    } else {
      return rexmpp_tcp_connected(conn,
                                  conn->sockets[conn->connection_attempts]);
    }
    conn->connection_attempts++;
    return REXMPP_CONN_IN_PROGRESS;
  }
  conn->resolution_v4 = REXMPP_CONN_RESOLUTION_WAITING;
  conn->resolution_v6 = REXMPP_CONN_RESOLUTION_WAITING;

  rexmpp_dns_resolve(s, host, 28, 1,
                     conn, rexmpp_tcp_dns_aaaa_cb);
  rexmpp_dns_resolve(s, host, 1, 1,
                     conn, rexmpp_tcp_dns_a_cb);

  return REXMPP_CONN_IN_PROGRESS;
}

int rexmpp_tcp_conn_finish (rexmpp_tcp_conn_t *conn) {
  rexmpp_tcp_cleanup(conn);
  return conn->fd;
}

int rexmpp_tcp_conn_ipv4_available(rexmpp_tcp_conn_t *conn) {
  return (conn->resolution_v4 == REXMPP_CONN_RESOLUTION_SUCCESS &&
          conn->resolved_v4 != NULL &&
          conn->resolved_v4->data[conn->addr_cur_v4 + 1] != NULL);
}

int rexmpp_tcp_conn_ipv6_available(rexmpp_tcp_conn_t *conn) {
  return (conn->resolution_v6 == REXMPP_CONN_RESOLUTION_SUCCESS &&
          conn->resolved_v6 != NULL &&
          conn->resolved_v6->data[conn->addr_cur_v6 + 1] != NULL);
}

rexmpp_tcp_conn_error_t
rexmpp_tcp_conn_proceed (rexmpp_t *s,
                         rexmpp_tcp_conn_t *conn,
                         fd_set *read_fds,
                         fd_set *write_fds)
{
  (void)read_fds;     /* Not checking any read FDs at the moment. */
  struct timeval now;
  int i;

  /* Check for successful connections. */
  for (i = 0; i < REXMPP_TCP_MAX_CONNECTION_ATTEMPTS; i++) {
    int err;
    socklen_t err_len = sizeof(err);
    if (conn->sockets[i] != -1 && FD_ISSET(conn->sockets[i], write_fds)) {
      if (getsockopt(conn->sockets[i], SOL_SOCKET, SO_ERROR, &err, &err_len)) {
        return REXMPP_CONN_ERROR;
      } else {
        if (err == 0) {
          return rexmpp_tcp_connected(conn, conn->sockets[i]);
        } else if (err != EINPROGRESS) {
          close(conn->sockets[i]);
          conn->sockets[i] = -1;
        }
      }
    }
  }

  /* Name resolution. */
  if (conn->resolution_v4 == REXMPP_CONN_RESOLUTION_WAITING ||
      conn->resolution_v6 == REXMPP_CONN_RESOLUTION_WAITING) {
    rexmpp_dns_process(s, read_fds, write_fds);
  }

  if (conn->resolution_v4 == REXMPP_CONN_RESOLUTION_FAILURE &&
      conn->resolution_v6 == REXMPP_CONN_RESOLUTION_FAILURE) {
    /* Failed to resolve anything. */
    return REXMPP_CONN_FAILURE;
  }

  /* New connections. */
  int repeat;
  do {
    repeat = 0;
    if (conn->connection_attempts < REXMPP_TCP_MAX_CONNECTION_ATTEMPTS &&
        (rexmpp_tcp_conn_ipv4_available(conn) ||
         rexmpp_tcp_conn_ipv6_available(conn))) {
      gettimeofday(&now, NULL);
      if (now.tv_sec > conn->next_connection_time.tv_sec ||
          (now.tv_sec == conn->next_connection_time.tv_sec &&
           now.tv_usec >= conn->next_connection_time.tv_usec)) {
        /* Time to attempt a new connection. */
        int use_ipv6 = 0;
        if (rexmpp_tcp_conn_ipv4_available(conn) &&
            rexmpp_tcp_conn_ipv6_available(conn)) {
          if (conn->addr_cur_v4 >= conn->addr_cur_v6) {
            use_ipv6 = 1;
          }
        } else if (rexmpp_tcp_conn_ipv6_available(conn)) {
          use_ipv6 = 1;
        }

        struct sockaddr_in6 addr_v6;
        struct sockaddr_in addr_v4;
        struct sockaddr *addr;
        socklen_t addrlen;
        int domain;
        int len;

        if (use_ipv6) {
          conn->addr_cur_v6++;
          len = sizeof(addr_v6.sin6_addr);
          if (len > conn->resolved_v6->len[conn->addr_cur_v6]) {
            len = conn->resolved_v6->len[conn->addr_cur_v6];
          }
          memcpy(&addr_v6.sin6_addr,
                 conn->resolved_v6->data[conn->addr_cur_v6],
                 len);
          addr_v6.sin6_family = AF_INET6;
          addr_v6.sin6_port = htons(conn->port);
          domain = AF_INET6;
          addr = (struct sockaddr*)&addr_v6;
          addrlen = sizeof(addr_v6);
        } else {
          conn->addr_cur_v4++;
          len = sizeof(addr_v4.sin_addr);
          if (len > conn->resolved_v4->len[conn->addr_cur_v4]) {
            len = conn->resolved_v4->len[conn->addr_cur_v4];
          }
          memcpy(&addr_v4.sin_addr,
                 conn->resolved_v4->data[conn->addr_cur_v4],
                 len);
          addr_v4.sin_family = AF_INET;
          addr_v4.sin_port = htons(conn->port);
          domain = AF_INET;
          addr = (struct sockaddr*)&addr_v4;
          addrlen = sizeof(addr_v4);
        }

        conn->sockets[conn->connection_attempts] =
          socket(domain, SOCK_STREAM, 0);
        int flags = fcntl(conn->sockets[conn->connection_attempts], F_GETFL, 0);
        fcntl(conn->sockets[conn->connection_attempts], F_SETFL, flags | O_NONBLOCK);
        if (connect(conn->sockets[conn->connection_attempts], addr, addrlen)) {
          if (errno == EINPROGRESS) {
            gettimeofday(&(conn->next_connection_time), NULL);
            conn->next_connection_time.tv_usec += REXMPP_TCP_CONN_DELAY_MS * 1000;
            if (conn->next_connection_time.tv_usec >= 1000000) {
              conn->next_connection_time.tv_usec -= 1000000;
              conn->next_connection_time.tv_sec++;
            }
            conn->connection_attempts++;
          } else {
            close(conn->sockets[conn->connection_attempts]);
            conn->sockets[conn->connection_attempts] = -1;
            if (conn->connection_attempts < REXMPP_TCP_MAX_CONNECTION_ATTEMPTS &&
                (rexmpp_tcp_conn_ipv4_available(conn) ||
                 rexmpp_tcp_conn_ipv6_available(conn))) {
              repeat = 1;
            }
          }
        } else {
          return rexmpp_tcp_connected(conn,
                                      conn->sockets[conn->connection_attempts]);
        }
      }
    }
  } while (repeat);

  int active_connections = 0;
  for (i = 0; i < REXMPP_TCP_MAX_CONNECTION_ATTEMPTS; i++) {
    if (conn->sockets[i] != -1) {
      active_connections++;
      break;
    }
  }

  gettimeofday(&now, NULL);

  if (active_connections ||
      conn->resolution_v4 == REXMPP_CONN_RESOLUTION_WAITING ||
      conn->resolution_v6 == REXMPP_CONN_RESOLUTION_WAITING ||
      (conn->next_connection_time.tv_sec > now.tv_sec ||
       (conn->next_connection_time.tv_sec == now.tv_sec &&
        conn->next_connection_time.tv_usec > now.tv_usec))) {
    return REXMPP_CONN_IN_PROGRESS;
  } else {
    return REXMPP_CONN_FAILURE;
  }
}

int rexmpp_tcp_conn_fds (rexmpp_t *s,
                         rexmpp_tcp_conn_t *conn,
                         fd_set *read_fds,
                         fd_set *write_fds)
{
  int max_fd = 0, i;
  if (conn->resolution_v4 == REXMPP_CONN_RESOLUTION_WAITING ||
      conn->resolution_v6 == REXMPP_CONN_RESOLUTION_WAITING) {
    max_fd = rexmpp_dns_fds(s, read_fds, write_fds);
  }
  for (i = 0; i < REXMPP_TCP_MAX_CONNECTION_ATTEMPTS; i++) {
    if (conn->sockets[i] != -1) {
      FD_SET(conn->sockets[i], write_fds);
      if (max_fd < conn->sockets[i] + 1) {
        max_fd = conn->sockets[i] + 1;
      }
    }
  }
  return max_fd;
}

struct timeval *rexmpp_tcp_conn_timeout (rexmpp_t *s,
                                         rexmpp_tcp_conn_t *conn,
                                         struct timeval *max_tv,
                                         struct timeval *tv)
{
  struct timeval now;
  struct timeval *ret = max_tv;
  if (conn->resolution_v4 == REXMPP_CONN_RESOLUTION_WAITING ||
      conn->resolution_v6 == REXMPP_CONN_RESOLUTION_WAITING) {
    ret = rexmpp_dns_timeout(s, max_tv, tv);
  }
  if (conn->resolution_v4 == REXMPP_CONN_RESOLUTION_SUCCESS ||
      conn->resolution_v6 == REXMPP_CONN_RESOLUTION_SUCCESS ||
      (conn->resolution_v4 == REXMPP_CONN_RESOLUTION_INACTIVE &&
       conn->resolution_v6 == REXMPP_CONN_RESOLUTION_INACTIVE)) {
    gettimeofday(&now, NULL);
    if (now.tv_sec < conn->next_connection_time.tv_sec ||
        (now.tv_sec == conn->next_connection_time.tv_sec &&
         now.tv_usec <= conn->next_connection_time.tv_usec)) {
      if (ret == NULL ||
          ret->tv_sec > conn->next_connection_time.tv_sec - now.tv_sec ||
          (ret->tv_sec == conn->next_connection_time.tv_sec - now.tv_sec &&
           ret->tv_usec > conn->next_connection_time.tv_usec - now.tv_usec)) {
        ret = tv;
        tv->tv_sec = conn->next_connection_time.tv_sec - now.tv_sec;
        if (conn->next_connection_time.tv_usec > now.tv_usec) {
          tv->tv_usec = conn->next_connection_time.tv_usec - now.tv_usec;
        } else {
          tv->tv_usec = conn->next_connection_time.tv_usec + 1000000 - now.tv_usec;
          tv->tv_sec--;
        }
      }
    }
  }
  return ret;
}
