/**
   @file rexmpp_socks.c
   @brief SOCKS5 connection establishment.
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#include <memory.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "rexmpp_socks.h"

enum socks_err
rexmpp_socks_proceed (rexmpp_socks_t *s)
{
  ssize_t ret;
  if (s->io_state == REXMPP_SOCKS_WRITING) {
    ssize_t ret = send(s->fd, s->buf + s->buf_sent,
                        s->buf_len - s->buf_sent, 0);
    if (ret > 0) {
      s->buf_sent += ret;
      if (s->buf_len == s->buf_sent) {
        s->buf_len = 0;
        s->io_state = REXMPP_SOCKS_READING;
      }
    } else if (errno == EAGAIN) {
      return REXMPP_SOCKS_E_AGAIN;
    } else {
      return REXMPP_SOCKS_E_TCP;
    }
  } else if (s->io_state == REXMPP_SOCKS_READING) {
    ret = recv(s->fd, s->buf + s->buf_len,
               REXMPP_SOCKS_BUF_LEN - s->buf_len, 0);
    if (ret > 0) {
      s->buf_len += ret;
      if (s->buf[0] != 5) {
        return REXMPP_SOCKS_E_VERSION;
      }
      if (s->buf_len >= 2) {
        s->socks_error = s->buf[1];
      }
      if (s->stage == REXMPP_SOCKS_AUTH) {
        if (s->buf_len > 2) {
          return REXMPP_SOCKS_E_REPLY;
        }
        if (s->buf_len == 2) {
          if (s->socks_error != 0) {
            return REXMPP_SOCKS_E_SOCKS;
          }
          /* It's okay to not authenticate, now we send a command. */
          s->buf[0] = 5;      /* SOCKS version 5 */
          s->buf[1] = 1;      /* Connect */
          s->buf[2] = 0;      /* Reserved */
          s->buf[3] = 3;      /* Domain name (todo: IP addresses) */
          size_t len = strlen(s->host);
          s->buf[4] = len;
          memcpy(s->buf + 5, s->host, len);
          uint16_t port = htons(s->port);
          memcpy(s->buf + 5 + len, &port, 2);
          s->buf_len = 7 + len;
          s->buf_sent = 0;
          s->stage = REXMPP_SOCKS_CMD;
          s->io_state = REXMPP_SOCKS_WRITING;
          return rexmpp_socks_proceed(s);
        }
      } else if (s->stage == REXMPP_SOCKS_CMD) {
        if (s->buf_len >= 5) {
          size_t full_len = 6;
          if (s->buf[3] == 1) { /* IPv4 */
            full_len += 4;
          } else if (s->buf[3] == 3) { /* Domain name */
            full_len += s->buf[4] + 1;
          } else if (s->buf[3] == 4) { /* IPv6 */
            full_len += 16;
          } else {
            return REXMPP_SOCKS_E_REPLY;
          }
          if (s->buf_len > full_len) {
            return REXMPP_SOCKS_E_REPLY;
          }
          if (s->buf_len == full_len) {
            if (s->socks_error != 0) {
              return REXMPP_SOCKS_E_SOCKS;
            }
            /* We're done. */
            s->stage = REXMPP_SOCKS_DONE;
            return REXMPP_SOCKS_CONNECTED;
          }
        }
      }
    } else if (errno == EAGAIN) {
      return REXMPP_SOCKS_E_AGAIN;
    } else {
      return REXMPP_SOCKS_E_TCP;
    }
  }
  return REXMPP_SOCKS_E_AGAIN;
}

enum socks_err
rexmpp_socks_init (rexmpp_socks_t *s,
                   int fd,
                   const char *host,
                   uint16_t port)
{
  s->fd = fd;
  s->host = host;
  s->port = port;
  s->socks_error = 0;

  if (strlen(host) > 255) {
    return REXMPP_SOCKS_E_HOST;
  }

  /* Request authentication. */
  s->stage = REXMPP_SOCKS_AUTH;
  s->io_state = REXMPP_SOCKS_WRITING;
  s->buf[0] = 5;                /* SOCKS version 5 */
  s->buf[1] = 1;                /* 1 supported method */
  s->buf[2] = 0;                /* "no authentication required" */
  s->buf_len = 3;
  s->buf_sent = 0;
  return rexmpp_socks_proceed(s);
}
