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
#elif defined(USE_CARES)
#include <ares.h>
#else
#endif
#include <netdb.h>


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
  free(result);
}

rexmpp_dns_result_t *result_from_hostent (struct hostent *hostinfo) {
  rexmpp_dns_result_t *r = malloc(sizeof(rexmpp_dns_result_t));
  r->secure = 0;
  int i, size = 0;
  while (hostinfo->h_addr_list[size] != NULL) {
    size++;
  }
  r->data = malloc(sizeof(void *) * (size + 1));
  r->len = malloc(sizeof(int) * size);
  for (i = 0; i < size; i++) {
    r->len[i] = hostinfo->h_length;
    r->data[i] = malloc(r->len[i]);
    memcpy(r->data[i], hostinfo->h_addr_list[i], hostinfo->h_length);
  }
  r->data[size] = NULL;
  return r;
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
#elif defined(USE_CARES)
  int err = ares_library_init(ARES_LIB_INIT_ALL);
  if (err != 0) {
    rexmpp_log(s, LOG_CRIT, "ares library initialisation error: %s",
               ares_strerror(err));
    return 1;
  }
  err = ares_init(&(s->resolver.channel));
  if (err) {
    rexmpp_log(s, LOG_CRIT, "ares channel initialisation error: %s",
               ares_strerror(err));
    ares_library_cleanup();
    return 1;
  }
  return 0;
#else
  (void)s;
  return 0;
#endif
}

void rexmpp_dns_ctx_cleanup (rexmpp_t *s) {
  (void)s;
  return;
}

void rexmpp_dns_ctx_deinit (rexmpp_t *s) {
#if defined(USE_UNBOUND)
  if (s->resolver.ctx != NULL) {
    ub_ctx_delete(s->resolver.ctx);
    s->resolver.ctx = NULL;
  }
#elif defined(USE_CARES)
  ares_destroy(s->resolver.channel);
  ares_library_cleanup();
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
#elif defined(USE_CARES)
  return ares_fds(s->resolver.channel, read_fds, write_fds);
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
#elif defined(USE_CARES)
  return ares_timeout(s->resolver.channel, max_tv, tv);
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
    rexmpp_log(s, LOG_WARNING, "DNS query failure: %s",
               ub_strerror(err));
    ub_resolve_free(result);
    d->cb(s, d->ptr, NULL);
    free(d);
    return;
  }

  if (result->bogus) {
    rexmpp_log(s, LOG_WARNING,
               "Received a bogus DNS resolution result");
    ub_resolve_free(result);
    d->cb(s, d->ptr, NULL);
    return;
  }

  if (! result->havedata) {
    rexmpp_log(s, LOG_DEBUG, "No data in the query result");
    ub_resolve_free(result);
    d->cb(s, d->ptr, NULL);
    free(d);
    return;
  }

  int i, size = 0;
  while (result->data[size] != NULL) {
    size++;
  }
  rexmpp_dns_result_t *res = malloc(sizeof(rexmpp_dns_result_t));
  res->data = malloc(sizeof(void *) * (size + 1));
  res->len = malloc(sizeof(int) * size);
  for (i = 0; i < size; i++) {
    if (result->qtype == 33) {
      /* SRV */
      res->len[i] = sizeof(rexmpp_dns_srv_t);
      res->data[i] = malloc(res->len[i]);
      int err = rexmpp_parse_srv(result->data[i], result->len[i],
                                 (rexmpp_dns_srv_t*)res->data[i]);
      if (err) {
        rexmpp_log(s, LOG_WARNING, "Failed to parse an SRV record");
        res->data[i + 1] = NULL;
        rexmpp_dns_result_free(res);
        d->cb(s, d->ptr, NULL);
        free(d);
        return;
      }
    } else {
      /* Non-SRV, for now that's just A or AAAA */
      res->len[i] = result->len[i];
      res->data[i] = malloc(res->len[i]);
      memcpy(res->data[i], result->data[i], res->len[i]);
    }
  }
  res->data[size] = NULL;
  res->secure = result->secure;
  ub_resolve_free(result);
  d->cb(s, d->ptr, res);
  free(d);
}
#elif defined(USE_CARES)
void rexmpp_dns_cb (void *ptr,
                    int err,
                    int timeouts,
                    unsigned char *abuf,
                    int alen)
{
  (void)timeouts;
  struct rexmpp_dns_query_cb_data *d = ptr;
  rexmpp_t *s = d->s;
  if (err != ARES_SUCCESS) {
    rexmpp_log(s, LOG_WARNING, "A DNS query failure: %s",
               ares_strerror(err));
    d->cb(s, d->ptr, NULL);
    free(d);
    return;
  }
  /* c-ares won't just tell us the type, but it does check for it in
     the parsing functions, so we just try them out. */
  struct hostent *hostinfo;
  struct ares_srv_reply *srv, *cur_srv;
  if (ares_parse_a_reply(abuf, alen, &hostinfo, NULL, NULL) == ARES_SUCCESS ||
      ares_parse_aaaa_reply(abuf, alen, &hostinfo, NULL, NULL) == ARES_SUCCESS) {
    rexmpp_dns_result_t *r = result_from_hostent(hostinfo);
    ares_free_hostent(hostinfo);
    d->cb(s, d->ptr, r);
  } else if (ares_parse_srv_reply(abuf, alen, &srv) == ARES_SUCCESS) {
    int i, size;
    for (size = 0, cur_srv = srv; cur_srv != NULL; size++, cur_srv = cur_srv->next);
    rexmpp_dns_result_t *r = malloc(sizeof(rexmpp_dns_result_t));
    r->secure = 0;
    r->data = malloc(sizeof(void*) * (size + 1));
    r->len = malloc(sizeof(int) * size);
    for (cur_srv = srv, i = 0; i < size; i++, cur_srv = cur_srv->next) {
      r->len[i] = sizeof(rexmpp_dns_srv_t);
      rexmpp_dns_srv_t *r_srv = malloc(sizeof(rexmpp_dns_srv_t));
      r_srv->priority = cur_srv->priority;
      r_srv->weight = cur_srv->weight;
      r_srv->port = cur_srv->port;
      strncpy(r_srv->target, cur_srv->host, 255);
      r_srv->target[255] = '\0';
      r->data[i] = r_srv;
    }
    r->data[size] = NULL;
    ares_free_data(srv);
    d->cb(s, d->ptr, r);
  } else {
    rexmpp_log(s, LOG_ERR, "Failed to parse a query");
    d->cb(s, d->ptr, NULL);
  }
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
#elif defined(USE_CARES)
  struct rexmpp_dns_query_cb_data *d =
    malloc(sizeof(struct rexmpp_dns_query_cb_data));
  d->s = s;
  d->cb = callback;
  d->ptr = ptr;
  ares_query(s->resolver.channel, query, rrclass, rrtype, rexmpp_dns_cb, d);
#else
  if (rrclass == 1) {
    if (rrtype == 1 || rrtype == 28) {
      struct hostent *hostinfo = gethostbyname(query);
      if (hostinfo == NULL) {
        rexmpp_log(s, LOG_ERR, "Failed to lookup %s", query);
        callback(s, ptr, NULL);
      } else {
        rexmpp_dns_result_t *r = result_from_hostent(hostinfo);
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
#elif defined(USE_CARES)
  ares_process(s->resolver.channel, read_fds, write_fds);
  return 0;
#else
  (void)s;
  (void)read_fds;
  (void)write_fds;
  return 0;
#endif
}
