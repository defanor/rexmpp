/**
   @file rexmpp_openpgp.c
   @brief XEP-0373 routines
   @author defanor <defanor@uberspace.net>
   @date 2020--2021
   @copyright MIT license.


Implementation notes
====================

XEP-0373 v0.6 is implemented here.

Intentionally omitted functionality:

- Not including a `to` element for self, since it is redundant for
  signed messages, and only useful for signed ones.

- Private key synchronisation is not implemented, since it is
  unnecessary in the presence of asynchronous cryptography and support
  for multiple keys, but can be dangerous if a passphrase used for key
  encryption is weaker than the key itself.

- XEP-0374 is not implemented here, since restricting its usage to
  `<signcrypt/>` is likely to be undesirable in some cases (primarily
  because it introduces non-repudiation).

Possible future improvements:

- A setting to generate the keys if they are missing, upload them
  automatically, encrypt messages opportunistically (as the XEP
  suggests).

- Maybe use alternative key retrieval methods in order to decrease
  dependency on PEP/pubsub, and possibly to incorporate existing
  infrastructure: e.g., retrieval by PEP-provided fingerprint from key
  servers, by vCard-provided email address from WKD or DANE.

*/

#include <syslog.h>
#include <string.h>
#include <time.h>

#include "config.h"

#ifdef HAVE_GPGME
#include <gpgme.h>
#endif
#include <libxml/tree.h>
#include <gsasl.h>

#include "rexmpp.h"
#include "rexmpp_openpgp.h"
#include "rexmpp_jid.h"
#include "rexmpp_pubsub.h"


#ifdef HAVE_GPGME

void rexmpp_pgp_fp_reply (rexmpp_t *s,
                          void *ptr,
                          xmlNodePtr req,
                          xmlNodePtr response,
                          int success)
{
  (void)ptr;
  (void)req;                    /* Not of interest. */
  if (! success) {
    rexmpp_log(s, LOG_WARNING, "Failed to retrieve an OpenpPGP key");
    return;
  }
  xmlNodePtr pubsub =
    rexmpp_xml_find_child(response, "http://jabber.org/protocol/pubsub",
                          "pubsub");
  if (pubsub == NULL) {
    rexmpp_log(s, LOG_ERR, "OpenPGP key retrieval: not a pubsub response");
    return;
  }
  xmlNodePtr items =
     rexmpp_xml_find_child(pubsub, "http://jabber.org/protocol/pubsub",
                           "items");
  if (items == NULL) {
    rexmpp_log(s, LOG_ERR, "OpenPGP key retrieval: no items in pubsub element");
    return;
  }
  xmlNodePtr item =
    rexmpp_xml_find_child(items, "http://jabber.org/protocol/pubsub", "item");
  if (item == NULL) {
    rexmpp_log(s, LOG_ERR, "OpenPGP key retrieval: no item in items");
    return;
  }
  xmlNodePtr pubkey =
    rexmpp_xml_find_child(item, "urn:xmpp:openpgp:0", "pubkey");
  if (pubkey == NULL) {
    rexmpp_log(s, LOG_ERR, "OpenPGP key retrieval: no pubkey in item");
    return;
  }
  xmlNodePtr data =
    rexmpp_xml_find_child(pubkey, "urn:xmpp:openpgp:0", "data");
  if (data == NULL) {
    rexmpp_log(s, LOG_ERR, "OpenPGP key retrieval: no data in pubkey");
    return;
  }

  char *key_raw = NULL;
  size_t key_raw_len = 0;
  char *key_base64 = xmlNodeGetContent(data);
  int sasl_err =
    gsasl_base64_from(key_base64, strlen(key_base64), &key_raw, &key_raw_len);
  free(key_base64);
  if (sasl_err != GSASL_OK) {
    rexmpp_log(s, LOG_ERR, "Base-64 key decoding failure: %s",
               gsasl_strerror(sasl_err));
    return;
  }

  gpgme_error_t err;
  gpgme_data_t key_dh;

  gpgme_data_new_from_mem(&key_dh, key_raw, key_raw_len, 0);
  err = gpgme_op_import(s->pgp_ctx, key_dh);
  /* Apparently reading GPGME results is not thread-safe. Fortunately
     it's not critical. */
  gpgme_import_result_t r = gpgme_op_import_result(s->pgp_ctx);

  gpgme_data_release(key_dh);
  if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
    rexmpp_log(s, LOG_WARNING, "OpenPGP key import error: %s",
               gpgme_strerror(err));
    return;
  }
  if (r->imported == 1) {
    rexmpp_log(s, LOG_DEBUG, "Imported a key");
  } else {
    rexmpp_log(s, LOG_WARNING, "Key import failure");
  }
}

rexmpp_err_t
rexmpp_openpgp_check_keys (rexmpp_t *s,
                           const char *jid,
                           xmlNodePtr items)
{
  xmlNodePtr item =
    rexmpp_xml_find_child(items, "http://jabber.org/protocol/pubsub#event",
                          "item");
  xmlNodePtr list =
      rexmpp_xml_find_child(item, "urn:xmpp:openpgp:0", "public-keys-list");
  xmlNodePtr metadata;
  for (metadata = xmlFirstElementChild(list);
       metadata != NULL;
       metadata = xmlNextElementSibling(metadata)) {
    char *fingerprint = xmlGetProp(metadata, "v4-fingerprint");
    gpgme_key_t key;
    gpgme_error_t err;
    err = gpgme_get_key(s->pgp_ctx, fingerprint, &key, 0);
    if (key != NULL) {
      gpgme_key_unref(key);
    }
    if (gpg_err_code(err) == GPG_ERR_EOF) {
      rexmpp_log(s, LOG_DEBUG,
                 "Unknown OpenPGP key fingerprint for %s: %s",
                 jid, fingerprint);
      xmlNodePtr fp_req = xmlNewNode(NULL, "pubsub");
      xmlNewNs(fp_req, "http://jabber.org/protocol/pubsub", NULL);
      xmlNodePtr fp_req_items = xmlNewNode(NULL, "items");
      xmlNewProp(fp_req_items, "max_items", "1");
      char key_node[72];
      snprintf(key_node, 72, "urn:xmpp:openpgp:0:public-keys:%s", fingerprint);
      xmlNewProp(fp_req_items, "node", key_node);
      xmlAddChild(fp_req, fp_req_items);
      rexmpp_iq_new(s, "get", jid, fp_req, rexmpp_pgp_fp_reply, NULL);
    } else if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
      rexmpp_log(s, LOG_WARNING,
                 "OpenPGP error when looking for a key: %s",
                 gpgme_strerror(err));
    }
    free(fingerprint);
  }

  return REXMPP_SUCCESS;
}

xmlNodePtr rexmpp_published_fingerprints (rexmpp_t *s, const char *jid) {
  xmlNodePtr published =
    rexmpp_find_event(s, jid, "urn:xmpp:openpgp:0:public-keys", NULL);
  if (published == NULL) {
    return NULL;
  }
  xmlNodePtr event =
    rexmpp_xml_find_child(published, "http://jabber.org/protocol/pubsub#event",
                          "event");
  xmlNodePtr items =
    rexmpp_xml_find_child(event, "http://jabber.org/protocol/pubsub#event",
                          "items");
  xmlNodePtr item =
    rexmpp_xml_find_child(items, "http://jabber.org/protocol/pubsub#event",
                          "item");
  xmlNodePtr list =
    rexmpp_xml_find_child(item, "urn:xmpp:openpgp:0",
                          "public-keys-list");
  xmlNodePtr published_fps = xmlFirstElementChild(list);
  return published_fps;
}

int rexmpp_openpgp_key_is_published (rexmpp_t *s, const char *fp) {
  xmlNodePtr metadata;
  for (metadata = rexmpp_published_fingerprints(s, s->assigned_jid.bare);
       metadata != NULL;
       metadata = xmlNextElementSibling(metadata)) {
    if (! rexmpp_xml_match(metadata, "urn:xmpp:openpgp:0", "pubkey-metadata")) {
      continue;
    }
    char *fingerprint = xmlGetProp(metadata, "v4-fingerprint");
    if (fingerprint == NULL) {
      rexmpp_log(s, LOG_WARNING, "No fingerprint found in pubkey-metadata");
      continue;
    }
    int matches = (strcmp(fingerprint, fp) == 0);
    free(fingerprint);
    if (matches) {
      return 1;
    }
  }
  return 0;
}

xmlNodePtr
rexmpp_openpgp_remove_key_from_list (rexmpp_t *s,
                                     const char *fp)
{
  xmlNodePtr fps =
    xmlCopyNodeList(rexmpp_published_fingerprints(s, s->assigned_jid.bare));
  xmlNodePtr metadata, prev = NULL;
  for (metadata = fps;
       metadata != NULL;
       prev = metadata, metadata = xmlNextElementSibling(metadata)) {
    if (! rexmpp_xml_match(metadata, "urn:xmpp:openpgp:0", "pubkey-metadata")) {
      continue;
    }
    char *fingerprint = xmlGetProp(metadata, "v4-fingerprint");
    if (fingerprint == NULL) {
      rexmpp_log(s, LOG_WARNING, "No fingerprint found in pubkey-metadata");
      continue;
    }
    int matches = (strcmp(fingerprint, fp) == 0);
    free(fingerprint);
    if (matches) {
      if (prev != NULL) {
        prev->next = metadata->next;
      } else {
        fps = metadata->next;
      }
      xmlFreeNode(metadata);
      return fps;
    }
  }
  return fps;
}

void rexmpp_pgp_key_publish_list_iq (rexmpp_t *s,
                                     void *ptr,
                                     xmlNodePtr req,
                                     xmlNodePtr response,
                                     int success)
{
  (void)ptr;
  (void)req;
  (void)response;
  if (! success) {
    rexmpp_log(s, LOG_WARNING, "Failed to publish an OpenpPGP key list");
    return;
  }
  rexmpp_log(s, LOG_INFO, "Published an OpenpPGP key list");
}

void rexmpp_pgp_key_fp_list_upload (rexmpp_t *s, xmlNodePtr metadata) {
  xmlNodePtr keylist = xmlNewNode(NULL, "public-keys-list");
  xmlNewNs(keylist, "urn:xmpp:openpgp:0", NULL);
  xmlAddChild(keylist, metadata);
  rexmpp_pubsub_item_publish(s, NULL, "urn:xmpp:openpgp:0:public-keys",
                             NULL, keylist, rexmpp_pgp_key_publish_list_iq, NULL);
}

void rexmpp_pgp_key_delete_iq (rexmpp_t *s,
                               void *ptr,
                               xmlNodePtr req,
                               xmlNodePtr response,
                               int success)
{
  (void)ptr;
  (void)response;
  if (! success) {
    rexmpp_log(s, LOG_WARNING, "Failed to delete an OpenpPGP key");
    return;
  }
  xmlNodePtr pubsub = xmlFirstElementChild(req);
  xmlNodePtr publish = xmlFirstElementChild(pubsub);
  char *node = xmlGetProp(publish, "node");
  char *fingerprint = node + 31;
  rexmpp_log(s, LOG_INFO, "Removed OpenpPGP key %s", fingerprint);
  free(node);
}

void rexmpp_pgp_key_publish_iq (rexmpp_t *s,
                                void *ptr,
                                xmlNodePtr req,
                                xmlNodePtr response,
                                int success)
{
  (void)ptr;
  (void)response;
  if (! success) {
    rexmpp_log(s, LOG_WARNING, "Failed to publish an OpenpPGP key");
    return;
  }
  rexmpp_log(s, LOG_INFO, "Uploaded an OpenpPGP key");
  xmlNodePtr pubsub = xmlFirstElementChild(req);
  xmlNodePtr publish = xmlFirstElementChild(pubsub);
  char *node = xmlGetProp(publish, "node");
  char *fingerprint = node + 31;

  char time_str[42];
  time_t t = time(NULL);
  struct tm utc_time;
  gmtime_r(&t, &utc_time);
  strftime(time_str, 42, "%FT%TZ", &utc_time);

  xmlNodePtr metadata = xmlNewNode(NULL, "pubkey-metadata");
  xmlNewNs(metadata, "urn:xmpp:openpgp:0", NULL);
  xmlNewProp(metadata, "date", time_str);
  xmlNewProp(metadata, "v4-fingerprint", fingerprint);

  free(node);

  xmlNodePtr fps = rexmpp_openpgp_remove_key_from_list(s, fingerprint);
  if (fps != NULL) {
    metadata->next = xmlCopyNodeList(fps);
  }
  rexmpp_pgp_key_fp_list_upload(s, metadata);
}

void rexmpp_openpgp_retract_key (rexmpp_t *s, const char *fp) {
  xmlNodePtr new_fp_list = rexmpp_openpgp_remove_key_from_list(s, fp);
  if (new_fp_list != NULL) {
    rexmpp_pgp_key_fp_list_upload(s, new_fp_list);
  }
  char node_str[72];
  snprintf(node_str, 72, "urn:xmpp:openpgp:0:public-keys:%s", fp);
  rexmpp_pubsub_node_delete(s, NULL, node_str, rexmpp_pgp_key_delete_iq, NULL);
}

rexmpp_err_t rexmpp_openpgp_publish_key (rexmpp_t *s, const char *fp) {
  if (strlen(fp) != 40) {
    rexmpp_log(s, LOG_ERR, "Wrong fingerprint length: %d", strlen(fp));
    return REXMPP_E_PGP;
  }

  gpgme_data_t key_dh;
  gpgme_error_t err;

  err = gpgme_data_new(&key_dh);
  if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
    rexmpp_log(s, LOG_ERR, "Failed to create a gpgme data buffer: %s",
               gpgme_strerror(err));
    return REXMPP_E_PGP;
  }
  gpgme_data_set_encoding(key_dh, GPGME_DATA_ENCODING_BINARY);
  err = gpgme_op_export(s->pgp_ctx, fp, 0, key_dh);
  if (gpg_err_code(err) == GPG_ERR_EOF) {
    rexmpp_log(s, LOG_ERR, "No such key found: %s", fp);
    gpgme_data_release(key_dh);
    return REXMPP_E_PGP;
  } else if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
    rexmpp_log(s, LOG_ERR, "Failed to read a key: %s", gpgme_strerror(err));
    gpgme_data_release(key_dh);
    return REXMPP_E_PGP;
  }
  char *key_raw, *key_base64 = NULL;
  size_t key_raw_len, key_base64_len = 0;
  key_raw = gpgme_data_release_and_get_mem(key_dh, &key_raw_len);
  gsasl_base64_to(key_raw, key_raw_len, &key_base64, &key_base64_len);
  free(key_raw);
  xmlNodePtr data = xmlNewNode(NULL, "data");
  xmlNewNs(data, "urn:xmpp:openpgp:0", NULL);
  xmlNodeAddContent(data, key_base64);
  free(key_base64);

  xmlNodePtr pubkey = xmlNewNode(NULL, "pubkey");
  xmlNewNs(pubkey, "urn:xmpp:openpgp:0", NULL);
  xmlAddChild(pubkey, data);

  char time_str[42];
  time_t t = time(NULL);
  struct tm utc_time;
  gmtime_r(&t, &utc_time);
  strftime(time_str, 42, "%FT%TZ", &utc_time);
  char node_str[72];
  snprintf(node_str, 72, "urn:xmpp:openpgp:0:public-keys:%s", fp);
  rexmpp_pubsub_item_publish(s, NULL, node_str, time_str,
                             pubkey, rexmpp_pgp_key_publish_iq, NULL);
  return REXMPP_SUCCESS;
}

int rexmpp_openpgp_fingerprint_matches (const char *f1, const char *f2) {
  int i = 0, j = 0;

  while (f1[i] || f2[j]) {
    /* skip spaces */
    while (f1[i] == ' ') i++;
    while (f2[j] == ' ') j++;
    /* compare */
    if (f1[i] != f2[j]) {
      return 0;
    }
    /* advance */
    i++;
    j++;
  }
  return 1;
}

xmlNodePtr
rexmpp_openpgp_decrypt_verify_message (rexmpp_t *s,
                                       xmlNodePtr message,
                                       int *valid)
{
  gpgme_error_t err;
  struct rexmpp_jid from, to;
  *valid = 0;
  if (! rexmpp_xml_match(message, "jabber:client", "message")) {
    rexmpp_log(s, LOG_ERR, "Not a message element");
    return NULL;
  }
  char *from_str = xmlGetProp(message, "from");
  if (from_str == NULL) {
    rexmpp_log(s, LOG_ERR, "No 'from' attribute");
    return NULL;
  }
  rexmpp_jid_parse(from_str, &from);
  free(from_str);
  char *to_str = xmlGetProp(message, "to");
  if (to_str == NULL) {
    if (strcmp(from.bare, s->assigned_jid.bare) != 0) {
      rexmpp_log(s, LOG_ERR, "No 'to' attribute");
      return NULL;
    }
    rexmpp_jid_parse(from.full, &to);
  } else {
    rexmpp_jid_parse(to_str, &to);
    free(to_str);
  }
  xmlNodePtr openpgp =
    rexmpp_xml_find_child(message, "urn:xmpp:openpgp:0", "openpgp");
  if (openpgp == NULL) {
    rexmpp_log(s, LOG_ERR, "No 'openpgp' child element");
    return NULL;
  }
  char *cipher_str = xmlNodeGetContent(openpgp);
  xmlNodePtr plain =
    rexmpp_openpgp_decrypt_verify(s, cipher_str);
  free(cipher_str);
  if (plain == NULL) {
    return NULL;
  }

  if (rexmpp_xml_match(plain, "urn:xmpp:openpgp:0", "crypt")) {
    *valid = 1;
    return plain;
  }

  if (! (rexmpp_xml_match(plain, "urn:xmpp:openpgp:0", "signcrypt") ||
         rexmpp_xml_match(plain, "urn:xmpp:openpgp:0", "sign"))) {
    rexmpp_log(s, LOG_ERR, "An unexpected element inside <openpgp/>");
    return plain;
  }

  xmlNodePtr child;
  int found = 0;
  for (child = xmlFirstElementChild(plain);
       child != NULL && ! found;
       child = xmlNextElementSibling(child))
    {
      if (rexmpp_xml_match(child, "urn:xmpp:openpgp:0", "to")) {
        char *to_jid = xmlGetProp(child, "jid");
        if (to_jid == NULL) {
          rexmpp_log(s, LOG_WARNING,
                     "Found a 'to' element without a 'jid' attribute");
        } else if (strcmp(to_jid, to.bare) == 0) {
          found = 1;
        }
        if (to_jid != NULL) {
          free(to_jid);
        }
      }
    }
  if (! found) {
    rexmpp_log(s, LOG_ERR,
               "No recipient corresponds to outer message's recipient");
    return plain;
  }

  gpgme_verify_result_t result = gpgme_op_verify_result(s->pgp_ctx);
  if (result == NULL) {
    rexmpp_log(s, LOG_ERR, "Signature verification failed");
    return plain;
  }

  gpgme_signature_t sig = result->signatures;
  if (sig->next != NULL) {
    rexmpp_log(s, LOG_WARNING,
               "Multiple signatures detected, verifying them all");
  }
  while (sig) {
    if (! sig->validity) {
      rexmpp_log(s, LOG_WARNING, "Invalid signature: %s",
                 gpgme_strerror(sig->validity_reason));
      return plain;
    }

    found = 0;
    xmlNodePtr metadata;
    for (metadata = rexmpp_published_fingerprints(s, from.bare);
         metadata != NULL && ! found;
         metadata = xmlNextElementSibling(metadata)) {
      char *fingerprint = xmlGetProp(metadata, "v4-fingerprint");
      if (fingerprint == NULL) {
        rexmpp_log(s, LOG_WARNING, "No fingerprint found in pubkey-metadata");
        continue;
      }
      if (rexmpp_openpgp_fingerprint_matches(fingerprint, sig->fpr)) {
        found = 1;
      }
      free(fingerprint);
    }
    if (! found) {
      rexmpp_log(s, LOG_ERR, "No %s's known key matches that of the signature",
                 from.bare);
      return plain;
    }
    gpgme_key_t key;
    err = gpgme_get_key(s->pgp_ctx, sig->fpr, &key, 0);
    if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
      rexmpp_log(s, LOG_ERR, "Key reading failure: %s",
                 gpgme_strerror(err));
      return plain;
    }
    gpgme_user_id_t uid;
    found = 0;
    for (uid = key->uids; uid != NULL; uid = uid->next) {
      if (strlen(uid->uid) < 6) {
        continue;
      }
      if (strncmp(uid->uid, "xmpp:", 5) == 0 &&
          strcmp(uid->uid + 5, from.bare) == 0) {
        found = 1;
      }
    }
    if (! found) {
      rexmpp_log(s, LOG_ERR,
                 "No 'xmpp:%s' user ID found in the key used for signature",
                 from.bare);
      return plain;
    }
    sig = sig->next;
  }

  *valid = 1;
  return plain;
}

xmlNodePtr
rexmpp_openpgp_decrypt_verify (rexmpp_t *s,
                               const char *cipher_base64)
{
  gpgme_error_t err;
  gpgme_data_t cipher_dh, plain_dh;
  char *cipher_raw = NULL, *plain;
  size_t cipher_raw_len = 0, plain_len;
  int sasl_err = gsasl_base64_from(cipher_base64, strlen(cipher_base64),
                                   &cipher_raw, &cipher_raw_len);
  if (sasl_err != GSASL_OK) {
    rexmpp_log(s, LOG_ERR, "Base-64 cipher decoding failure: %s",
               gsasl_strerror(sasl_err));
    return NULL;
  }
  gpgme_data_new_from_mem(&cipher_dh, cipher_raw, cipher_raw_len, 0);
  gpgme_data_new(&plain_dh);
  err = gpgme_op_decrypt_verify (s->pgp_ctx, cipher_dh, plain_dh);
  gpgme_data_release(cipher_dh);

  if (! (gpg_err_code(err) == GPG_ERR_NO_ERROR ||
         gpg_err_code(err) == GPG_ERR_NO_DATA)) {
    rexmpp_log(s, LOG_ERR, "Failed to decrypt/verify: %s", gpgme_strerror(err));
    gpgme_data_release(plain_dh);
    return NULL;
  }
  plain = gpgme_data_release_and_get_mem(plain_dh, &plain_len);
  if (plain == NULL) {
    rexmpp_log(s, LOG_ERR, "Failed to release and get memory");
    return NULL;
  }
  xmlNodePtr elem = rexmpp_xml_parse(plain, plain_len);
  if(elem == NULL) {
    rexmpp_log(s, LOG_ERR, "Failed to parse an XML document");
  }
  free(plain);
  return elem;
}

void rexmpp_openpgp_add_keys (rexmpp_t *s,
                              const char *jid,
                              gpgme_key_t **keys,
                              int *nkeys,
                              int *allocated)
{
  gpgme_error_t err;
  xmlNodePtr metadata;
  for (metadata = rexmpp_published_fingerprints(s, jid);
       metadata != NULL;
       metadata = xmlNextElementSibling(metadata)) {
    char *fingerprint = xmlGetProp(metadata, "v4-fingerprint");
    if (fingerprint == NULL) {
      rexmpp_log(s, LOG_WARNING, "No fingerprint found in pubkey-metadata");
      continue;
    }
    err = gpgme_get_key(s->pgp_ctx, fingerprint, &(*keys)[*nkeys], 0);
    if (gpg_err_code(err) == GPG_ERR_NO_ERROR) {
      if ((*keys)[*nkeys]->can_encrypt) {
        *nkeys = *nkeys + 1;
        if (*nkeys == *allocated) {
          *allocated = *allocated * 2;
          *keys = realloc(*keys, sizeof(gpgme_key_t *) * *allocated);
        }
      } else {
        gpgme_key_unref((*keys)[*nkeys]);
      }
      (*keys)[*nkeys] = NULL;
    } else if (gpg_err_code(err) == GPG_ERR_EOF) {
      rexmpp_log(s, LOG_WARNING, "No key %s for %s found",
                 fingerprint, jid);
    } else {
      rexmpp_log(s, LOG_ERR, "Failed to read key %s: %s",
                 fingerprint, gpgme_strerror(err));
    }
    free(fingerprint);
  }
}

void rexmpp_openpgp_set_signers (rexmpp_t *s) {
  gpgme_error_t err;
  xmlNodePtr metadata;
  gpgme_key_t sec_key;
  gpgme_signers_clear(s->pgp_ctx);
  for (metadata = rexmpp_published_fingerprints(s, s->initial_jid.bare);
       metadata != NULL;
       metadata = xmlNextElementSibling(metadata)) {
    char *fingerprint = xmlGetProp(metadata, "v4-fingerprint");
    if (fingerprint == NULL) {
      rexmpp_log(s, LOG_WARNING, "No fingerprint found in pubkey-metadata");
      continue;
    }
    err = gpgme_get_key(s->pgp_ctx, fingerprint, &sec_key, 1);
    if (gpg_err_code(err) == GPG_ERR_NO_ERROR) {
      if (sec_key->can_sign) {
        gpgme_signers_add(s->pgp_ctx, sec_key);
      }
      gpgme_key_unref(sec_key);
    } else if (gpg_err_code(err) != GPG_ERR_EOF) {
      rexmpp_log(s, LOG_ERR, "Failed to read key %s: %s",
                 fingerprint, gpgme_strerror(err));
    }
    free(fingerprint);
  }
}

char *rexmpp_openpgp_payload (rexmpp_t *s,
                              xmlNodePtr payload,
                              const char **recipients,
                              const char **signers,
                              enum rexmpp_ox_mode mode)
{
  gpgme_error_t err;
  int sasl_err;
  int i, nkeys = 0, allocated = 0;
  gpgme_key_t *keys = NULL;

  /* Prepare an element. */
  char *elem_name = NULL;
  if (mode == REXMPP_OX_SIGNCRYPT) {
    elem_name = "signcrypt";
  } else if (mode == REXMPP_OX_SIGN) {
    elem_name = "sign";
  } else if (mode == REXMPP_OX_CRYPT) {
    elem_name = "crypt";
  }
  xmlNodePtr elem = xmlNewNode(NULL, elem_name);
  xmlNewNs(elem, "urn:xmpp:openpgp:0", NULL);

  if (mode == REXMPP_OX_SIGN || mode == REXMPP_OX_SIGNCRYPT) {
    if (signers == NULL) {
      rexmpp_openpgp_set_signers(s);
    } else {
      gpgme_signers_clear(s->pgp_ctx);
      int signer;
      gpgme_key_t sec_key;
      for (signer = 0; signers[signer] != NULL; signer++) {
        err = gpgme_get_key(s->pgp_ctx, signers[signer], &sec_key, 1);
        if (gpg_err_code(err) == GPG_ERR_NO_ERROR) {
          gpgme_signers_add(s->pgp_ctx, sec_key);
          gpgme_key_unref(sec_key);
        } else {
          rexmpp_log(s, LOG_ERR, "Failed to read key %s: %s",
                     signers[signer], gpgme_strerror(err));
        }
      }
    }

    /* Add all the recipients. */
    for (i = 0; recipients[i] != NULL; i++) {
      xmlNodePtr to = xmlNewNode(NULL, "to");
      xmlNewNs(to, "urn:xmpp:openpgp:0", NULL);
      xmlNewProp(to, "jid", recipients[i]);
      xmlAddChild(elem, to);
    }
  }

  /* Add timestamp. */
  char time_str[42];
  time_t t = time(NULL);
  struct tm utc_time;
  gmtime_r(&t, &utc_time);
  strftime(time_str, 42, "%FT%TZ", &utc_time);
  xmlNodePtr time = xmlNewNode(NULL, "time");
  xmlNewNs(time, "urn:xmpp:openpgp:0", NULL);
  xmlNewProp(time, "stamp", time_str);
  xmlAddChild(elem, time);

  /* Add the payload. */
  xmlNodePtr pl = xmlNewNode(NULL, "payload");
  xmlNewNs(pl, "urn:xmpp:openpgp:0", NULL);
  xmlAddChild(pl, payload);
  xmlAddChild(elem, pl);

  if (mode == REXMPP_OX_CRYPT || mode == REXMPP_OX_SIGNCRYPT) {
    /* Add keys for encryption. */
    allocated = 8;
    keys = malloc(sizeof(gpgme_key_t *) * allocated);
    keys[0] = NULL;
    rexmpp_openpgp_add_keys(s, s->initial_jid.bare, &keys, &nkeys, &allocated);
    for (i = 0; recipients[i] != NULL; i++) {
      rexmpp_openpgp_add_keys(s, recipients[i], &keys, &nkeys, &allocated);
    }

    /* A random-length random-content padding. */
    char *rand_str, rand[256];
    gsasl_nonce(rand, 1);
    size_t rand_str_len = 0, rand_len = (unsigned char)rand[0] % (255 - 16) + 16;
    sasl_err = gsasl_nonce(rand, rand_len);
    if (sasl_err != GSASL_OK) {
      rexmpp_log(s, LOG_ERR, "Random generation failure: %s",
                 gsasl_strerror(sasl_err));
      return NULL;
    }
    sasl_err = gsasl_base64_to(rand, rand_len, &rand_str, &rand_str_len);
    if (sasl_err != GSASL_OK) {
      rexmpp_log(s, LOG_ERR, "Base-64 encoding failure: %s",
                 gsasl_strerror(sasl_err));
      return NULL;
    }

    xmlNodePtr rpad = xmlNewNode(NULL, "rpad");
    xmlNewNs(rpad, "urn:xmpp:openpgp:0", NULL);
    xmlNodeAddContent(rpad, rand_str);
    free(rand_str);
    xmlAddChild(elem, rpad);
  }

  /* Serialize the resulting XML. */
  char *plaintext = rexmpp_xml_serialize(elem);
  xmlFreeNode(elem);

  /* Encrypt, base64-encode. */
  gpgme_data_t cipher_dh, plain_dh;
  gpgme_data_new(&cipher_dh);
  gpgme_data_new_from_mem(&plain_dh, plaintext, strlen(plaintext), 0);
  if (mode == REXMPP_OX_SIGNCRYPT) {
    err = gpgme_op_encrypt_sign(s->pgp_ctx, keys, GPGME_ENCRYPT_NO_ENCRYPT_TO,
                                plain_dh, cipher_dh);
  } else if (mode == REXMPP_OX_CRYPT) {
    err = gpgme_op_encrypt(s->pgp_ctx, keys, GPGME_ENCRYPT_NO_ENCRYPT_TO,
                           plain_dh, cipher_dh);
  } else {                      /* if (mode == REXMPP_OX_SIGN) */
    err = gpgme_op_sign(s->pgp_ctx, plain_dh, cipher_dh, GPGME_SIG_MODE_NORMAL);
  }
  if (keys != NULL) {
    for (i = 0; i < nkeys; i++) {
      gpgme_key_unref(keys[i]);
    }
    free(keys);
    keys = NULL;
  }
  gpgme_data_release(plain_dh);
  if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
    rexmpp_log(s, LOG_ERR, "Failed to %s: %s", elem_name, gpgme_strerror(err));
    gpgme_data_release(cipher_dh);
    return NULL;
  }
  char *cipher_raw = NULL, *cipher_base64 = NULL;
  size_t cipher_raw_len = 0, cipher_base64_len = 0;
  cipher_raw = gpgme_data_release_and_get_mem(cipher_dh, &cipher_raw_len);
  gsasl_base64_to(cipher_raw, cipher_raw_len,
                  &cipher_base64, &cipher_base64_len);
  free(cipher_raw);

  return cipher_base64;
}

rexmpp_err_t rexmpp_openpgp_set_home_dir (rexmpp_t *s, const char *home_dir) {
  gpgme_engine_info_t engine_info;
  gpgme_error_t err;
  engine_info = gpgme_ctx_get_engine_info(s->pgp_ctx);
  err = gpgme_ctx_set_engine_info(s->pgp_ctx, engine_info->protocol,
                                  engine_info->file_name,
                                  home_dir);
  if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
    rexmpp_log(s, LOG_ERR, "Failed to set home directory: %s",
               gpgme_strerror(err));
    return REXMPP_E_PGP;
  }
  return REXMPP_SUCCESS;
}

#else

/* Dummy functions for when it's built without GPGME. */

rexmpp_err_t gpgme_not_supported(rexmpp_t *s) {
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without GPGME support");
  return REXMPP_E_PGP;
}

rexmpp_err_t
rexmpp_openpgp_check_keys (rexmpp_t *s,
                           const char *jid,
                           xmlNodePtr items) {
  (void)jid;
  (void)items;
  return gpgme_not_supported(s);
}

rexmpp_err_t rexmpp_openpgp_publish_key (rexmpp_t *s, const char *fp) {
  (void)fp;
  return gpgme_not_supported(s);
}

void rexmpp_openpgp_retract_key (rexmpp_t *s, const char *fp) {
  (void)fp;
  gpgme_not_supported(s);
}

xmlNodePtr
rexmpp_openpgp_decrypt_verify (rexmpp_t *s,
                               const char *cipher_base64) {
  (void)cipher_base64;
  gpgme_not_supported(s);
  return  NULL;
}

xmlNodePtr
rexmpp_openpgp_decrypt_verify_message (rexmpp_t *s,
                                       xmlNodePtr message,
                                       int *valid) {
  (void)message;
  (void)valid;
  gpgme_not_supported(s);
  return NULL;
}

char *rexmpp_openpgp_payload (rexmpp_t *s,
                              xmlNodePtr payload,
                              const char **recipients,
                              const char **signers,
                              enum rexmpp_ox_mode mode) {
  (void)recipients;
  (void)signers;
  (void)mode;
  xmlFreeNode(payload);
  gpgme_not_supported(s);
  return NULL;
}

rexmpp_err_t rexmpp_openpgp_set_home_dir (rexmpp_t *s, const char *home_dir) {
  (void)home_dir;
  return gpgme_not_supported(s);
}

#endif
