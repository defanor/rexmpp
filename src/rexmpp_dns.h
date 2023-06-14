/**
   @file rexmpp_dns.h
   @brief DNS resolution
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.

*/


#ifndef REXMPP_DNS_H
#define REXMPP_DNS_H

#include <stdint.h>
#include "config.h"

#include "rexmpp.h"

/**
   @brief DNS context.
*/
#if defined(USE_UNBOUND)
#include <unbound.h>
typedef struct ub_ctx* rexmpp_dns_ctx_t;
/* struct rexmpp_dns_ctx { */
/*   struct ub_ctx *ctx; */
/* }; */
#elif defined(USE_CARES)
#include <ares.h>
typedef ares_channel rexmpp_dns_ctx_t;
/* struct rexmpp_dns_ctx { */
/*   ares_channel channel; */
/* }; */
#else
typedef void* rexmpp_dns_ctx_t;
#endif

/* typedef struct rexmpp_dns_ctx rexmpp_dns_ctx_t; */

struct rexmpp_dns_srv {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  char target[256];
};

typedef struct rexmpp_dns_srv rexmpp_dns_srv_t;

/**
   @brief DNS query result.
*/
struct rexmpp_dns_result {
  /** @brief NULL-terminated array of data pointers. They contain
      ::rexmpp_dns_srv for SRV lookups, host addresses for A and AAAA
      ones. */
  void **data;
  /** @brief An array of data structure lengths. */
  int *len;
  /** @brief Whether the result was retrieved securely (that is,
      verified with DNSSEC). */
  int secure;
};

typedef struct rexmpp_dns_result rexmpp_dns_result_t;

/**
   @brief Parses an SRV DNS RR's RDATA.
   @param[in] in SRV record's RDATA.
   @param[in] in_len Length of the input data in octets.
   @param[out] out A structure to fill with data.
   @returns 0 on success, non-zero on parsing failure.
*/
int
rexmpp_parse_srv (char *in, int in_len, struct rexmpp_dns_srv *out);

/**
   @brief Frees a ::rexmpp_dns_result structure and its members.
   @param[in] result A pointer to a ::rexmpp_dns_result structure.
*/
void rexmpp_dns_result_free (rexmpp_dns_result_t *result);

/**
   @brief Initializes a DNS resolver context.
*/
int rexmpp_dns_ctx_init (rexmpp_t *s);

/**
   @brief Cleans up the state that can be discarded between XMPP
   connections, to be called from rexmpp_cleanup.
*/
void rexmpp_dns_ctx_cleanup (rexmpp_t *s);

/**
   @brief Deinitializes a DNS resolver context.
*/
void rexmpp_dns_ctx_deinit (rexmpp_t *s);

/**
   @brief Sets file descriptors to select/poll.
*/
int rexmpp_dns_fds (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds);

/**
   @brief Reports timeouts.
*/
struct timespec * rexmpp_dns_timeout (rexmpp_t *s,
                                      struct timespec *max_tv,
                                      struct timespec *tv);

typedef void (*dns_query_cb_t) (rexmpp_t *s, void *ptr, rexmpp_dns_result_t *result);

/**
   @brief Initiates a query.
*/
int rexmpp_dns_resolve (rexmpp_t *s,
                        const char *query,
                        int rrtype,
                        int rrclass,
                        void* ptr,
                        dns_query_cb_t callback);

/**
   @brief Processes active queries, should be called based on the
   reported timeouts and file descriptors.
*/
int rexmpp_dns_process (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds);


#endif
