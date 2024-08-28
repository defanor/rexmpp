/**
   @file rexmpp_sasl.h
   @brief SASL
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.

*/


#ifndef REXMPP_SASL_H
#define REXMPP_SASL_H

#include "config.h"

#include "rexmpp.h"

/** @brief These correspond to Gsasl_property values. */
typedef enum {
  /* Information properties, e.g., username. */
  REXMPP_SASL_PROP_AUTHID = 1,
  REXMPP_SASL_PROP_AUTHZID = 2,
  REXMPP_SASL_PROP_PASSWORD = 3,
  REXMPP_SASL_PROP_ANONYMOUS_TOKEN = 4,
  REXMPP_SASL_PROP_SERVICE = 5,
  REXMPP_SASL_PROP_HOSTNAME = 6,
  REXMPP_SASL_PROP_GSSAPI_DISPLAY_NAME = 7,
  REXMPP_SASL_PROP_PASSCODE = 8,
  REXMPP_SASL_PROP_SUGGESTED_PIN = 9,
  REXMPP_SASL_PROP_PIN = 10,
  REXMPP_SASL_PROP_REALM = 11,
  REXMPP_SASL_PROP_DIGEST_MD5_HASHED_PASSWORD = 12,
  REXMPP_SASL_PROP_QOPS = 13,
  REXMPP_SASL_PROP_QOP = 14,
  REXMPP_SASL_PROP_SCRAM_ITER = 15,
  REXMPP_SASL_PROP_SCRAM_SALT = 16,
  REXMPP_SASL_PROP_SCRAM_SALTED_PASSWORD = 17,
  REXMPP_SASL_PROP_SCRAM_SERVERKEY = 23,
  REXMPP_SASL_PROP_SCRAM_STOREDKEY = 24,
  REXMPP_SASL_PROP_CB_TLS_UNIQUE = 18,
  REXMPP_SASL_PROP_SAML20_IDP_IDENTIFIER = 19,
  REXMPP_SASL_PROP_SAML20_REDIRECT_URL = 20,
  REXMPP_SASL_PROP_OPENID20_REDIRECT_URL = 21,
  REXMPP_SASL_PROP_OPENID20_OUTCOME_DATA = 22,
  REXMPP_SASL_PROP_CB_TLS_EXPORTER = 25,
  /* Client callbacks. */
  REXMPP_SASL_PROP_SAML20_AUTHENTICATE_IN_BROWSER = 250,
  REXMPP_SASL_PROP_OPENID20_AUTHENTICATE_IN_BROWSER = 251,
  /* Server validation callback properties. */
  REXMPP_SASL_PROP_VALIDATE_SIMPLE = 500,
  REXMPP_SASL_PROP_VALIDATE_EXTERNAL = 501,
  REXMPP_SASL_PROP_VALIDATE_ANONYMOUS = 502,
  REXMPP_SASL_PROP_VALIDATE_GSSAPI = 503,
  REXMPP_SASL_PROP_VALIDATE_SECURID = 504,
  REXMPP_SASL_PROP_VALIDATE_SAML20 = 505,
  REXMPP_SASL_PROP_VALIDATE_OPENID20 = 506
} rexmpp_sasl_property;

/**
   @brief SASL context.
*/
#ifdef HAVE_GSASL
#include <gsasl.h>
struct rexmpp_sasl_ctx {
  Gsasl *ctx;
  Gsasl_session *session;
};
#else
typedef enum {
  REXMPP_SASL_MECH_EXTERNAL,
  REXMPP_SASL_MECH_PLAIN,
  REXMPP_SASL_MECH_UNKNOWN
} rexmpp_sasl_mechanism;

struct rexmpp_sasl_ctx {
  rexmpp_sasl_mechanism mech;
  char *authid;
  char *password;
};
#endif

typedef struct rexmpp_sasl_ctx rexmpp_sasl_ctx_t;

/**
   @brief Initializes SASL context.
*/
int rexmpp_sasl_ctx_init (rexmpp_t *s);

/**
   @brief Cleans up the state that can be discarded between XMPP
   connections, to be called from rexmpp_cleanup.
*/
void rexmpp_sasl_ctx_cleanup (rexmpp_t *s);

/**
   @brief Deinitializes a SASL context.
*/
void rexmpp_sasl_ctx_deinit (rexmpp_t *s);


int rexmpp_sasl_encode (rexmpp_t *s, const char *in, size_t in_len, char **out, size_t *out_len);
int rexmpp_sasl_decode (rexmpp_t *s, const char *in, size_t in_len, char **out, size_t *out_len);

const char *rexmpp_sasl_suggest_mechanism (rexmpp_t *s, const char *mech_list);
const char *rexmpp_sasl_mechanism_name (rexmpp_t *s);

int rexmpp_sasl_start (rexmpp_t *s, const char *mech);
int rexmpp_sasl_step64 (rexmpp_t *s, const char *b64_in, char **b64_out);

void rexmpp_sasl_property_set (rexmpp_t *s, rexmpp_sasl_property prop, const char *data);

#endif
