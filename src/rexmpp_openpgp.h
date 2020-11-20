/**
   @file rexmpp_openpgp.h
   @brief XEP-0373 routines
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/
#ifndef REXMPP_OPENPGP_H
#define REXMPP_OPENPGP_H

#include "rexmpp.h"

rexmpp_err_t
rexmpp_openpgp_check_keys (rexmpp_t *s,
                           const char *jid,
                           xmlNodePtr items);

rexmpp_err_t rexmpp_openpgp_publish_key (rexmpp_t *s, const char *fp);

xmlNodePtr
rexmpp_openpgp_decrypt_verify (rexmpp_t *s,
                               const char *cipher_base64);

xmlNodePtr
rexmpp_openpgp_decrypt_verify_message (rexmpp_t *s,
                                       xmlNodePtr message,
                                       int *valid);

char *rexmpp_openpgp_encrypt_sign (rexmpp_t *s,
                                   xmlNodePtr payload,
                                   char **recipients);

#endif
