/**
   @file rexmpp_dns.c
   @brief DNS helper functions
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#include <memory.h>
#include <syslog.h>

#include "config.h"

#if defined(USE_UNBOUND)
#include <unbound.h>
#else
#include <netdb.h>
#endif

#include "rexmpp.h"
#include "rexmpp_dns.h"


struct rexmpp_dns_query_cb_data {
  rexmpp_t *s;
  dns_query_cb_t cb;
  void *ptr;
};



/* https://tools.ietf.org/html/rfc1035#section-3.1 */

int rexmpp_dns_parse_qname (char *in, int in_len, char *out, int out_len) {
  int i = 0;
  while (i < in_len && in[i]) {
    if (i + in[i] < in_len && i + in[i] < out_len) {
      memcpy(out + i, in + i + 1, in[i]);
      i += in[i];
      out[i] = '.';
      i++;
      out[i] = '\0';
    } else {
      return -1;
    }
  }
  return i;
}

int rexmpp_parse_srv (char *in, int in_len, struct rexmpp_dns_srv *out) {
  if (in_len < 7 || in_len > 255 + 6) {
    return -1;
  }
  out->priority = in[0] * 0x100 + in[1];
  out->weight = in[2] * 0x100 + in[3];
  out->port = in[4] * 0x100 + in[5];
  if (rexmpp_dns_parse_qname(in + 6, in_len - 6, out->target, 255) < 0) {
    return -1;
  }
  return 0;
}


void rexmpp_dns_result_free (rexmpp_dns_result_t *result) {
  if (result->data != NULL) {
    int i;
    for (i = 0; result->data[i] != NULL; i++) {
      free(result->data[i]);
    }
    free(result->data);
    result->data = NULL;
  }
  if (result->len != NULL) {
    free(result->len);
    result->len = NULL;
  }
  if (result->qname != NULL) {
    free(result->qname);
    result->qname = NULL;
  }
  free(result);
}


int rexmpp_dns_ctx_init (rexmpp_t *s) {
#if defined(USE_UNBOUND)
  int err;
  s->resolver.ctx = ub_ctx_create();
  if (s->resolver.ctx == NULL) {
    rexmpp_log(s, LOG_CRIT, "Failed to create resolver context");
    return 1;
  }
  err = ub_ctx_resolvconf(s->resolver.ctx, NULL);
  if (err != 0) {
    rexmpp_log(s, LOG_WARNING, "Failed to read resolv.conf: %s",
               ub_strerror(err));
  }
  err = ub_ctx_hosts(s->resolver.ctx, NULL);
  if (err != 0) {
    rexmpp_log(s, LOG_WARNING, "Failed to read hosts file: %s",
               ub_strerror(err));
  }
  err = ub_ctx_add_ta_file(s->resolver.ctx, DNSSEC_TRUST_ANCHOR_FILE);
  if (err != 0) {
    rexmpp_log(s, LOG_WARNING, "Failed to set root key file for DNSSEC: %s",
               ub_strerror(err));
  }
  return 0;
#else
  (void)s;
  return 0;
#endif
}

void rexmpp_dns_ctx_cleanup (rexmpp_t *s) {
#if defined(USE_UNBOUND)
  (void)s;
  return;
#else
  (void)s;
  return;
#endif
}

void rexmpp_dns_ctx_deinit (rexmpp_t *s) {
#if defined(USE_UNBOUND)
  if (s->resolver.ctx != NULL) {
    ub_ctx_delete(s->resolver.ctx);
    s->resolver.ctx = NULL;
  }
#else
  (void)s;
#endif
}

int rexmpp_dns_fds (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds) {
#if defined(USE_UNBOUND)
  (void)write_fds;
  int max_fd = ub_fd(s->resolver.ctx) + 1;
  if (max_fd != 0) {
    FD_SET(max_fd - 1, read_fds);
  }
  return max_fd;
#else
  (void)s;
  (void)read_fds;
  (void)write_fds;
  return 0;
#endif
}

struct timeval * rexmpp_dns_timeout (rexmpp_t *s,
                                     struct timeval *max_tv,
                                     struct timeval *tv)
{
#if defined(USE_UNBOUND)
  (void)s;
  (void)tv;
  return max_tv;
#else
  (void)s;
  (void)max_tv;
  (void)tv;
  return max_tv;
#endif
}

#if defined(USE_UNBOUND)
void rexmpp_dns_cb (void *ptr,
                    int err,
                    struct ub_result *result)
{
  struct rexmpp_dns_query_cb_data *d = ptr;
  rexmpp_t *s = d->s;

  if (err != 0) {
    rexmpp_log(s, LOG_WARNING, "%s DNS query failure: %s",
               result->qname, ub_strerror(err));
    ub_resolve_free(result);
    d->cb(s, d->ptr, NULL);
    return;
  }

  if (result->bogus) {
    rexmpp_log(s, LOG_WARNING,
               "Received a bogus DNS resolution result for %s",
               result->qname);
    ub_resolve_free(result);
    d->cb(s, d->ptr, NULL);
    return;
  }

  if (! result->havedata) {
    rexmpp_log(s, LOG_DEBUG, "No data in the %s query result", result->qname);
    ub_resolve_free(result);
    d->cb(s, d->ptr, NULL);
    return;
  }

  int i, size = 0;
  while (result->data[size] != NULL) {
    size++;
  }
  rexmpp_dns_result_t *res = malloc(sizeof(rexmpp_dns_result_t));
  res->data = malloc(sizeof(char *) * (size + 1));
  res->len = malloc(sizeof(int) * size);
  for (i = 0; i < size; i++) {
    res->len[i] = result->len[i];
    res->data[i] = malloc(res->len[i]);
    memcpy(res->data[i], result->data[i], res->len[i]);
  }
  res->data[size] = NULL;
  res->secure = result->secure;
  res->qname = strdup(result->qname);
  ub_resolve_free(result);
  d->cb(s, d->ptr, res);
  free(d);
}
#endif


int rexmpp_dns_resolve (rexmpp_t *s,
                        const char *query,
                        int rrtype,
                        int rrclass,
                        void* ptr,
                        dns_query_cb_t callback)
{
#if defined(USE_UNBOUND)
  struct rexmpp_dns_query_cb_data *d =
    malloc(sizeof(struct rexmpp_dns_query_cb_data));
  d->s = s;
  d->cb = callback;
  d->ptr = ptr;
  int err = ub_resolve_async(s->resolver.ctx, query, rrtype, rrclass,
                             d, rexmpp_dns_cb, NULL);
  if (err) {
    rexmpp_log(s, LOG_ERR, "Failed to query %s: %s",
               query, ub_strerror(err));
    return 1;
  }
#else
  rexmpp_dns_result_t *r = malloc(sizeof(rexmpp_dns_result_t));;
  if (rrclass == 1) {
    if (rrtype == 1 || rrtype == 28) {
      struct hostent *hostinfo = gethostbyname(query);
      if (hostinfo == NULL) {
        rexmpp_log(s, LOG_ERR, "Failed to lookup %s", query);
        callback(s, ptr, NULL);
      } else {
        r->qname = strdup(query);
        r->secure = 0;
        int i, size = 0;
        while (hostinfo->h_addr_list[size] != NULL) {
          size++;
        }
        r->data = malloc(sizeof(char *) * (size + 1));
        r->len = malloc(sizeof(int) * size);
        for (i = 0; i < size; i++) {
          r->len[i] = hostinfo->h_length;
          r->data[i] = malloc(r->len[i]);
          memcpy(r->data[i], hostinfo->h_addr_list[i], hostinfo->h_length);
        }
        r->data[size] = NULL;
        callback(s, ptr, r);
      }
    } else if (rrtype == 33) {
      rexmpp_log(s, LOG_WARNING, "rexmpp is built without SRV lookup support");
      callback(s, ptr, NULL);
    } else {
      rexmpp_log(s, LOG_ERR, "A DNS lookup of unrecognized type is requested");
      callback(s, ptr, NULL);
      return -1;
    }
  } else {
    rexmpp_log(s, LOG_ERR, "A DNS lookup of unrecognized class is requested");
    callback(s, ptr, NULL);
    return -1;
  }
#endif
  return 0;
}

int rexmpp_dns_process (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds) {
#if defined(USE_UNBOUND)
  (void)read_fds;
  (void)write_fds;
  if (ub_poll(s->resolver.ctx)) {
    int err = ub_process(s->resolver.ctx);
    if (err != 0) {
      rexmpp_log(s, LOG_ERR, "DNS query processing error: %s",
                 ub_strerror(err));
      return 1;
    }
  }
  return 0;
#else
  (void)s;
  (void)read_fds;
  (void)write_fds;
  return 0;
#endif
}
