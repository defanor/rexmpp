/**
   @file rexmpp_tcp.h
   @brief TCP connection establishment.
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.

   This module tries to establish a TCP connection to a given host
   and port.

   A connection establishment procedure begins with
   ::rexmpp_tcp_conn_init, followed by repeated calls to
   ::rexmpp_tcp_conn_proceed while the return code is
   ::REXMPP_CONN_IN_PROGRESS, at the times suggested by
   ::rexmpp_tcp_conn_timeout and on events suggested by
   ::rexmpp_tcp_conn_fds, and ends with ::rexmpp_tcp_conn_finish.
*/

#ifndef REXMPP_TCP_H
#define REXMPP_TCP_H

#define REXMPP_TCP_MAX_CONNECTION_ATTEMPTS 20
#define REXMPP_TCP_IPV6_DELAY_MS 50
#define REXMPP_TCP_CONN_DELAY_MS 250

typedef enum rexmpp_tcp_conn_resolution_status
rexmpp_tcp_conn_resolution_status_t;

/**
   @brief Resolution status.
 */
enum rexmpp_tcp_conn_resolution_status {
  /** The resolution is not active. */
  REXMPP_CONN_RESOLUTION_INACTIVE,
  /** Waiting for resolution. */
  REXMPP_CONN_RESOLUTION_WAITING,
  /** Resolved successfully. */
  REXMPP_CONN_RESOLUTION_SUCCESS,
  /** Failed to resolve. */
  REXMPP_CONN_RESOLUTION_FAILURE
};

typedef enum rexmpp_tcp_conn_error rexmpp_tcp_conn_error_t;

/**
   @brief Connection errors.
*/
enum rexmpp_tcp_conn_error {
  /** Connected, no error. */
  REXMPP_CONN_DONE,
  /** Resolver error occurred. The exact error code can be read from
      the connection structure. */
  REXMPP_CONN_RESOLVER_ERROR,
  /** Connection in progress, no error yet. */
  REXMPP_CONN_IN_PROGRESS,
  /** All the connection attempts failed. */
  REXMPP_CONN_FAILURE,
  /** An unexpected error during connection. */
  REXMPP_CONN_ERROR
};

typedef struct rexmpp_tcp_connection rexmpp_tcp_conn_t;

/** @brief A connection establishment structure. */
struct rexmpp_tcp_connection {
  /** @brief A host we are connecting to. */
  const char *host;
  /** @brief A port we are connecting to. */
  uint16_t port;

  /** @brief Resolver context. */
  struct ub_ctx *resolver_ctx;
  /** @brief Resolver error is stored here when
      ::REXMPP_CONN_RESOLVER_ERROR is returned. */
  int resolver_error;

  /** @brief State of A record resolution. */
  enum rexmpp_tcp_conn_resolution_status resolution_v4;
  /** @brief Status of A record resolution, as returned by the
      resolver. */
  int resolver_status_v4;
  /** @brief Resolved A records. */
  struct ub_result *resolved_v4;
  /** @brief The AF_INET address number we are currently at. */
  int addr_cur_v4;

  /** @brief State of AAAA record resolution. */
  enum rexmpp_tcp_conn_resolution_status resolution_v6;
  /** @brief Status of AAAA record resolution, as returned by the
      resolver. */
  int resolver_status_v6;
  /** @brief Resolved AAAA records. */
  struct ub_result *resolved_v6;
  /** @brief The AF_INET6 address number we are currently at. */
  int addr_cur_v6;

  /** @brief Socket array, one for each connection attempt. */
  int sockets[REXMPP_TCP_MAX_CONNECTION_ATTEMPTS];
  /** @brief The number of connection attempts so far. */
  int connection_attempts;

  /** @brief Next scheduled connection time. */
  struct timeval next_connection_time;
  /** @brief File descriptor of a connected socket. */
  int fd;
  /** @brief Whether the A or AAAA records used to establish the final
      connection were verified with DNSSEC. */
  int dns_secure;
};

/**
    @brief Initiates a connection.
    @param[out] conn An allocated connection structure.
    @param[in] resolver_ctx Resolver context to use.
    @param[in] host A host to connect to. This could be a domain name,
    or a textual representation of an IPv4 or an IPv6 address.
    @param[in] port A port to connect to.
    @returns A ::rexmpp_tcp_conn_error state.
*/
rexmpp_tcp_conn_error_t
rexmpp_tcp_conn_init (rexmpp_tcp_conn_t *conn,
                      struct ub_ctx *resolver_ctx,
                      const char *host,
                      uint16_t port);

/**
    @brief Continues a connection process.
    @param[in,out] conn An active connection structure.
    @param[in] read_fds File descriptors available for reading from.
    @param[in] write_fds File descriptors available for writing to.
    @returns A ::rexmpp_tcp_conn_error state.
*/
rexmpp_tcp_conn_error_t
rexmpp_tcp_conn_proceed (rexmpp_tcp_conn_t *conn,
                         fd_set *read_fds,
                         fd_set *write_fds);

/**
   @brief Finalises a connection process.

   Closes pending connections except for the established one, frees
   additionally allocated resources.

   Normally must be called on any state other than
   ::REXMPP_CONN_IN_PROGRESS. The connection structure can be freed
   after this.

   @param[in,out] conn An active connection structure.
   @returns A connected socket's file descriptor, or -1.
 */
int rexmpp_tcp_conn_finish (rexmpp_tcp_conn_t *conn);

/**
   @brief Reports file descriptors a connection process is interested in.

   File descriptors are only added to an @c fd_set, so the ones it
   already contains will not be lost.

   @param[in] conn An active connection structure.
   @param[out] read_fds File descriptors a connection process is
   interested in reading from.
   @param[out] write_fds File descriptors a connection process is
   interested in writing to.
   @returns Maximum file descriptor number, plus 1.
 */
int rexmpp_tcp_conn_fds (rexmpp_tcp_conn_t *conn,
                         fd_set *read_fds,
                         fd_set *write_fds);

/**
   @brief Reports timeouts.
   @param[in] conn An active connection structure.
   @param[in] max_tv An existing maximum timeout.
   @param[out] tv A timeval structure to store a new timeout in.
   @returns A pointer to either max_tv or tv, depending on which one
   is smaller.
*/
struct timeval *rexmpp_tcp_conn_timeout (rexmpp_tcp_conn_t *conn,
                                         struct timeval *max_tv,
                                         struct timeval *tv);

#endif
