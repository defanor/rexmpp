/**
   @file rexmpp_socks.h
   @brief SOCKS5 connection establishment.
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#ifndef REXMPP_SOCKS_H
#define REXMPP_SOCKS_H

#include <unistd.h>


#define REXMPP_SOCKS_BUF_LEN 300


enum socks_io_state {
  REXMPP_SOCKS_WRITING,
  REXMPP_SOCKS_READING
};

enum socks_stage {
  REXMPP_SOCKS_AUTH,
  REXMPP_SOCKS_CMD,
  REXMPP_SOCKS_DONE
};

enum socks_err {
  REXMPP_SOCKS_CONNECTED,
  REXMPP_SOCKS_E_AGAIN,
  REXMPP_SOCKS_E_TCP,
  REXMPP_SOCKS_E_REPLY,
  REXMPP_SOCKS_E_VERSION,
  REXMPP_SOCKS_E_SOCKS,
  REXMPP_SOCKS_E_HOST
};

struct rexmpp_socks {
  int fd;
  const char *host;
  uint16_t port;
  enum socks_stage stage;
  enum socks_io_state io_state;
  int socks_error;
  char buf[REXMPP_SOCKS_BUF_LEN];
  size_t buf_len;
  size_t buf_sent;
};
typedef struct rexmpp_socks rexmpp_socks_t;


enum socks_err
rexmpp_socks_proceed (rexmpp_socks_t *s);

enum socks_err
rexmpp_socks_init (rexmpp_socks_t *s,
                   int fd,
                   const char *host,
                   uint16_t port);


#endif
