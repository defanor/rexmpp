/**
   @file rexmpp_openpgp.h
   @brief XEP-0373 routines
   @author defanor <defanor@uberspace.net>
   @date 2020--2021
   @copyright MIT license.
*/
#ifndef REXMPP_OPENPGP_H
#define REXMPP_OPENPGP_H

#include "rexmpp.h"

/**
   @brief A mode corresponding to XEP-0373's OpenPGP content element.
 */
enum rexmpp_ox_mode {
  REXMPP_OX_SIGN,
  REXMPP_OX_CRYPT,
  REXMPP_OX_SIGNCRYPT
};

/**
   @brief Checks whether we have all the keys from the list of known
   keys for a given JID, requests missing ones.
   @param[in] s ::rexmpp
   @param[in] jid A JID.
   @param[in] items An <items> element with <public-keys-list> in it.
*/
rexmpp_err_t
rexmpp_openpgp_check_keys (rexmpp_t *s,
                           const char *jid,
                           xmlNodePtr items);

/**
   @brief Publishes a key via PEP/pubsub.
   @param[in] s ::rexmpp
   @param[in] fp The fingerprint of a key that should be published.
   @returns ::REXMPP_SUCCESS or an error code.
*/
rexmpp_err_t rexmpp_openpgp_publish_key (rexmpp_t *s, const char *fp);

/**
   @brief Retracts a key from PEP/pubsub.
   @param[in] s ::rexmpp
   @param[in] fp The fingerprint of a key that should be deleted.
*/
void rexmpp_openpgp_retract_key (rexmpp_t *s, const char *fp);

/**
   @brief Tries to decrypt and/or verify an OpenPGP message.
   @param[in] s ::rexmpp
   @param[in] cipher_base64 An OpenPGP ciphertext.
   @returns A plaintext message body.
*/
xmlNodePtr
rexmpp_openpgp_decrypt_verify (rexmpp_t *s,
                               const char *cipher_base64);

/**
   @brief Tries to decrypt and/or verify an OpenPGP message from a
   <message> element, taking into account its attributes.
   @param[in] s ::rexmpp
   @param[in] message A <message> element.
   @param[out] valid Will be set to 1 if the message appears to be
   valid.
   @returns A decrypted message body.
*/
xmlNodePtr
rexmpp_openpgp_decrypt_verify_message (rexmpp_t *s,
                                       xmlNodePtr message,
                                       int *valid);

/**
   @brief Encodes a message, producing a signed and/or encrypted
   payload.
   @param[in] s ::rexmpp
   @param[in] payload XML payload.
   @param[in] recipients A NULL-terminated list of recipient JIDs.
   @param[in] mode ::rexmpp_ox_mode
   @returns An encoded <openpgp> payload.
*/
char *rexmpp_openpgp_payload (rexmpp_t *s,
                              xmlNodePtr payload,
                              const char **recipients,
                              enum rexmpp_ox_mode mode);


/**
   @brief An utility function for setting GPG home directory. An
   appropriate time to call it is right after rexmpp_init.
   @param[in] s ::rexmpp
   @param[in] home_dir Path to the home directory.
   @returns ::REXMPP_E_PGP or ::REXMPP_SUCCESS
*/
rexmpp_err_t rexmpp_openpgp_set_home_dir (rexmpp_t *s, const char *home_dir);


#endif
