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

/**
   @brief Whether we are reading or writing.
*/
enum socks_io_state {
  /** Attempting to send data to the server. */
  REXMPP_SOCKS_WRITING,
  /** Attempting to receive data from the server. */
  REXMPP_SOCKS_READING
};

/**
   @brief SOCKS5 connection stage.
*/
enum socks_stage {
  /** Authentication stage. */
  REXMPP_SOCKS_AUTH,
  /** Command sending stage. */
  REXMPP_SOCKS_CMD,
  /** Done. */
  REXMPP_SOCKS_DONE
};

/**
   @brief Status/error codes.
*/
enum socks_err {
  /** Connected successfully. */
  REXMPP_SOCKS_CONNECTED,
  /** Connection in progress. */
  REXMPP_SOCKS_E_AGAIN,
  /** A TCP error. */
  REXMPP_SOCKS_E_TCP,
  /** Malformed or unrecognised reply from a server. */
  REXMPP_SOCKS_E_REPLY,
  /** Wrong server SOCKS version. */
  REXMPP_SOCKS_E_VERSION,
  /** An error is reported by the server, the code is stored in
      ::rexmpp_socks's @c socks_error */
  REXMPP_SOCKS_E_SOCKS,
  /** Host name is too long (can be 255 bytes at most). */
  REXMPP_SOCKS_E_HOST
};

/**
   @brief SOCKS5 connection state.
*/
struct rexmpp_socks {
  /** @brief A file descriptor. */
  int fd;
  /** @brief A host we are connecting to. */
  const char *host;
  /** @brief A port we are connecting to. */
  uint16_t port;
  /** @brief Current connection stage. */
  enum socks_stage stage;
  /** @brief I/O state: whether we are reading or writing. */
  enum socks_io_state io_state;
  /** @brief A SOCKS5 error code, as returned by the server. */
  int socks_error;
  /** @brief A buffer used to receive and send packets. */
  char buf[REXMPP_SOCKS_BUF_LEN];
  /** @brief How many bytes of useful data are in the buffer. */
  size_t buf_len;
  /** @brief How many bytes were sent so far. */
  size_t buf_sent;
};
typedef struct rexmpp_socks rexmpp_socks_t;

/**
   @brief Continues a SOCKS5 connection establishment.
   @param[in,out] s An initialised ::rexmpp_socks structure.
   @returns A ::socks_err code.

   While ::REXMPP_SOCKS_E_AGAIN is returned, this function should be
   called repeatedly when the socket state is suitable for
   ::rexmpp_socks's ::socks_io_state.
*/
enum socks_err
rexmpp_socks_proceed (rexmpp_socks_t *s);

/**
   @brief Initialises a SOCKS5 connection over a connected socket.
   @param[out] s An allocated ::rexmpp_socks structure.
   @param[in] fd A socket file descriptor. This is supposed to be
   connected to a SOCKS5 server.
   @param[in] host A host to connect to.
   @param[in] port A port to connect to.
   @returns ::REXMPP_SOCKS_E_HOST or the return value of the first
   ::rexmpp_socks_proceed invocation.
*/
enum socks_err
rexmpp_socks_init (rexmpp_socks_t *s,
                   int fd,
                   const char *host,
                   uint16_t port);


#endif
