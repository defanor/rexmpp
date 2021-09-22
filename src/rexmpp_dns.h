/**
   @file rexmpp_dns.h
   @brief DNS helper functions
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/


#ifndef REXMPP_DNS_H
#define REXMPP_DNS_H

#include <stdint.h>
#include "config.h"

#include "rexmpp.h"

#if defined(USE_UNBOUND)
#include <unbound.h>
struct rexmpp_dns_ctx {
  struct ub_ctx *ctx;
};
#elif defined(USE_CARES)
#include <ares.h>
struct rexmpp_dns_ctx {
  ares_channel channel;
};
#else
struct rexmpp_dns_ctx {
  int dummy;
};
#endif

typedef struct rexmpp_dns_ctx rexmpp_dns_ctx_t;

struct rexmpp_dns_srv {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  char target[256];
};

typedef struct rexmpp_dns_srv rexmpp_dns_srv_t;

struct rexmpp_dns_result {
  void **data;
  int *len;
  int secure;
};

/**
   @brief Parses an SRV DNS RR's RDATA.
   @param[in] in SRV record's RDATA.
   @param[in] in_len Length of the input data in octets.
   @param[out] out A structure to fill with data.
   @returns 0 on success, non-zero on parsing failure.
*/
int
rexmpp_parse_srv (char *in, int in_len, struct rexmpp_dns_srv *out);

typedef struct rexmpp_dns_result rexmpp_dns_result_t;

/* struct rexmpp_dns_result *rexmpp_dns_result_init (int len); */
void rexmpp_dns_result_free (rexmpp_dns_result_t *result);

int rexmpp_dns_ctx_init (rexmpp_t *s);
void rexmpp_dns_ctx_cleanup (rexmpp_t *s);
void rexmpp_dns_ctx_deinit (rexmpp_t *s);
int rexmpp_dns_fds (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds);
struct timeval * rexmpp_dns_timeout (rexmpp_t *s,
                                     struct timeval *max_tv,
                                     struct timeval *tv);

typedef void (*dns_query_cb_t) (rexmpp_t *s, void *ptr, rexmpp_dns_result_t *result);

int rexmpp_dns_resolve (rexmpp_t *s,
                        const char *query,
                        int rrtype,
                        int rrclass,
                        void* ptr,
                        dns_query_cb_t callback);

int rexmpp_dns_process (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds);


#endif
