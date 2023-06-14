/**
   @file rexmpp_sasl.c
   @brief SASL
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.

*/

#include <syslog.h>

#include "config.h"
#include "rexmpp.h"
#include "rexmpp_sasl.h"
#include "rexmpp_base64.h"

#ifdef HAVE_GSASL
#include <gsasl.h>

int rexmpp_sasl_cb (Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop) {
  (void)sctx;      /* The session should already be in rexmpp_t. */
  rexmpp_t *s = gsasl_callback_hook_get(ctx);
  if (s == NULL || s->sasl_property_cb == NULL) {
    return GSASL_NO_CALLBACK;
  }
  if (s->sasl_property_cb(s, (rexmpp_sasl_property)prop) == 0) {
    return GSASL_OK;
  } else {
    return GSASL_NO_CALLBACK;
  }
}

int rexmpp_sasl_ctx_init (rexmpp_t *s) {
  s->sasl = malloc(sizeof(struct rexmpp_sasl_ctx));
  int err = gsasl_init(&(s->sasl->ctx));
  if (err != GSASL_OK) {
    rexmpp_log(s, LOG_CRIT, "gsasl initialisation error: %s",
               gsasl_strerror(err));
    return -1;
  }
  gsasl_callback_hook_set(s->sasl->ctx, s);
  gsasl_callback_set(s->sasl->ctx, rexmpp_sasl_cb);
  return 0;
}

void rexmpp_sasl_ctx_deinit (rexmpp_t *s) {
  gsasl_done(s->sasl->ctx);
  if (s->sasl != NULL) {
    free(s->sasl);
    s->sasl = NULL;
  }
}

void rexmpp_sasl_ctx_cleanup (rexmpp_t *s) {
  gsasl_finish(s->sasl->session);
  s->sasl->session = NULL;
}

int rexmpp_sasl_encode (rexmpp_t *s, const char *in, size_t in_len, char **out, size_t *out_len) {
  int sasl_err = gsasl_encode (s->sasl->session, in, in_len, out, out_len);
  if (sasl_err != GSASL_OK) {
    rexmpp_log(s, LOG_ERR, "SASL encoding error: %s", gsasl_strerror(sasl_err));
    return -1;
  }
  return 0;
}

int rexmpp_sasl_decode (rexmpp_t *s, const char *in, size_t in_len, char **out, size_t *out_len) {
  int sasl_err = gsasl_decode(s->sasl->session, in, in_len, out, out_len);
  if (sasl_err != GSASL_OK) {
    rexmpp_log(s, LOG_ERR, "SASL decoding error: %s", gsasl_strerror(sasl_err));
    return -1;
  }
  return 0;
}

const char *rexmpp_sasl_suggest_mechanism (rexmpp_t *s, const char *mech_list) {
  return gsasl_client_suggest_mechanism(s->sasl->ctx, mech_list);
}

void rexmpp_sasl_property_set (rexmpp_t *s, rexmpp_sasl_property prop, const char *data) {
  gsasl_property_set (s->sasl->session, (Gsasl_property)prop, data);
}

int rexmpp_sasl_start (rexmpp_t *s, const char *mech) {
  int sasl_err = gsasl_client_start(s->sasl->ctx, mech, &(s->sasl->session));
  if (sasl_err != GSASL_OK) {
    rexmpp_log(s, LOG_CRIT, "Failed to initialise SASL session: %s",
               gsasl_strerror(sasl_err));
    return -1;
  }
  return 0;
}

int rexmpp_sasl_step64 (rexmpp_t *s, const char *b64_in, char **b64_out) {
  int sasl_err = gsasl_step64 (s->sasl->session, b64_in, b64_out);
  if (sasl_err != GSASL_OK) {
    if (sasl_err == GSASL_NEEDS_MORE) {
      rexmpp_log(s, LOG_DEBUG, "SASL needs more data");
    } else {
      rexmpp_log(s, LOG_ERR, "SASL error: %s", gsasl_strerror(sasl_err));
      return -1;
    }
  }
  return 0;
}

#else

/* No GSASL. */
#include <memory.h>

int rexmpp_sasl_ctx_init (rexmpp_t *s) {
  s->sasl = malloc(sizeof(struct rexmpp_sasl_ctx));
  s->sasl->mech = REXMPP_SASL_MECH_UNKNOWN;
  s->sasl->authid = NULL;
  s->sasl->password = NULL;
  return 0;
}

void rexmpp_sasl_ctx_cleanup (rexmpp_t *s) {
  s->sasl->mech = REXMPP_SASL_MECH_UNKNOWN;
  if (s->sasl->authid != NULL) {
    free(s->sasl->authid);
    s->sasl->authid = NULL;
  }
  if (s->sasl->password != NULL) {
    free(s->sasl->password);
    s->sasl->password = NULL;
  }
}

void rexmpp_sasl_ctx_deinit (rexmpp_t *s)  {
  if (s->sasl != NULL) {
    free(s->sasl);
    s->sasl = NULL;
  }
}

int rexmpp_sasl_encode (rexmpp_t *s, const char *in, size_t in_len, char **out, size_t *out_len) {
  (void)s;
  *out = malloc(in_len);
  memcpy(*out, in, in_len);
  *out_len = in_len;
  return 0;
}
int rexmpp_sasl_decode (rexmpp_t *s, const char *in, size_t in_len, char **out, size_t *out_len) {
  (void)s;
  *out = malloc(in_len);
  memcpy(*out, in, in_len);
  *out_len = in_len;
  return 0;
}

rexmpp_sasl_mechanism rexmpp_sasl_mech_read (const char *mech) {
  if (mech == NULL) {
    return REXMPP_SASL_MECH_UNKNOWN;
  }
  if (strcmp(mech, "EXTERNAL") == 0) {
    return REXMPP_SASL_MECH_EXTERNAL;
  } else if (strcmp(mech, "PLAIN") == 0) {
    return REXMPP_SASL_MECH_PLAIN;
  } else {
    return REXMPP_SASL_MECH_UNKNOWN;
  }
}

const char *rexmpp_sasl_mech_name (rexmpp_sasl_mechanism mech) {
  if (mech == REXMPP_SASL_MECH_EXTERNAL) {
    return "EXTERNAL";
  } else if (mech == REXMPP_SASL_MECH_PLAIN) {
    return "PLAIN";
  } else {
    return NULL;
  }
}

const char *rexmpp_sasl_suggest_mechanism (rexmpp_t *s, const char *mech_list) {
  (void)s;
  char *mech, *save_ptr, *mlist = strdup(mech_list);
  mech = strtok_r(mlist, " ", &save_ptr);
  rexmpp_sasl_mechanism preferred = REXMPP_SASL_MECH_UNKNOWN;
  while (mech != NULL) {
    rexmpp_sasl_mechanism m = rexmpp_sasl_mech_read(mech);
    if (m == REXMPP_SASL_MECH_EXTERNAL ||
        (m == REXMPP_SASL_MECH_PLAIN && preferred == REXMPP_SASL_MECH_UNKNOWN)) {
      preferred = m;
    }
    mech = strtok_r(NULL, " ", &save_ptr);
  }
  free(mlist);
  return rexmpp_sasl_mech_name(preferred);
}

int rexmpp_sasl_start (rexmpp_t *s, const char *mech) {
  rexmpp_sasl_mechanism m = rexmpp_sasl_mech_read(mech);
  if (m != REXMPP_SASL_MECH_UNKNOWN) {
    s->sasl->mech = m;
    return 0;
  }
  return -1;
}

const char *rexmpp_sasl_get_prop (rexmpp_t *s, rexmpp_sasl_property prop) {
  if (prop == REXMPP_SASL_PROP_AUTHID) {
    if (s->sasl->authid == NULL) {
      s->sasl_property_cb(s, prop);
    }
    return s->sasl->authid;
  } else if (prop == REXMPP_SASL_PROP_PASSWORD) {
    if (s->sasl->password == NULL) {
      s->sasl_property_cb(s, prop);
    }
    return s->sasl->password;
  }
  return NULL;
}

int rexmpp_sasl_step64 (rexmpp_t *s, const char *b64_in, char **b64_out) {
  (void)s;
  (void)b64_in;
  if (s->sasl->mech == REXMPP_SASL_MECH_PLAIN) {
    /* RFC 4616 */
    const char *authid = rexmpp_sasl_get_prop(s, REXMPP_SASL_PROP_AUTHID);
    const char *password = rexmpp_sasl_get_prop(s, REXMPP_SASL_PROP_PASSWORD);
    if (authid != NULL && password != NULL) {
      size_t auth_len = strlen(authid) + strlen(password) + 2;
      char *auth = malloc(auth_len);
      auth[0] = 0;
      memcpy(auth + 1, authid, strlen(authid));
      auth[strlen(authid) + 1] = 0;
      memcpy(auth + strlen(authid) + 2, password, strlen(password));
      size_t out_len;
      rexmpp_base64_to(auth, auth_len, b64_out, &out_len);
      free(auth);
      return 0;
    }
  } else if (s->sasl->mech == REXMPP_SASL_MECH_EXTERNAL) {
    *b64_out = strdup("");
    return 0;
  }
  return -1;
}

void rexmpp_sasl_property_set (rexmpp_t *s, rexmpp_sasl_property prop, const char *data) {
  (void)s;
  (void)data;
  if (prop == REXMPP_SASL_PROP_AUTHID) {
    if (s->sasl->authid != NULL) {
      free(s->sasl->authid);
    }
    s->sasl->authid = strdup(data);
  } else if (prop == REXMPP_SASL_PROP_PASSWORD) {
    if (s->sasl->password != NULL) {
      free(s->sasl->password);
    }
    s->sasl->password = strdup(data);
  }
}

#endif
