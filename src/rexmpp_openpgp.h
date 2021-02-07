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
void rexmpp_openpgp_retract_key (rexmpp_t *s, const char *fp);

xmlNodePtr
rexmpp_openpgp_decrypt_verify (rexmpp_t *s,
                               const char *cipher_base64);

xmlNodePtr
rexmpp_openpgp_decrypt_verify_message (rexmpp_t *s,
                                       xmlNodePtr message,
                                       int *valid);

char *rexmpp_openpgp_encrypt_sign (rexmpp_t *s,
                                   xmlNodePtr payload,
                                   const char **recipients);

char *rexmpp_openpgp_encrypt (rexmpp_t *s,
                              xmlNodePtr payload,
                              const char **recipients);

char *rexmpp_openpgp_sign (rexmpp_t *s,
                           xmlNodePtr payload,
                           const char **recipients);

/**
   @brief An utility function for setting GPG home directory. An
   appropriate time to call it is right after rexmpp_init.
   @param[in] s ::rexmpp
   @param[in] home_dir Path to the home directory.
   @returns ::REXMPP_E_PGP or ::REXMPP_SUCCESS
*/
rexmpp_err_t rexmpp_openpgp_set_home_dir (rexmpp_t *s, const char *home_dir);


#endif
