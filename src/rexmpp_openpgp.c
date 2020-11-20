/**
   @file rexmpp_openpgp.c
   @brief XEP-0373 routines
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#include <syslog.h>
#include <string.h>

#include <gpgme.h>
#include <libxml/tree.h>
#include <gsasl.h>

#include "rexmpp.h"
#include "rexmpp_openpgp.h"


void rexmpp_pgp_fp_reply (rexmpp_t *s,
                          xmlNodePtr req,
                          xmlNodePtr response,
                          int success)
{
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
  char *key_base64 = xmlNodeGetContent(data);

  char *key_raw = NULL;
  size_t key_raw_len = 0;
  int sasl_err =
    gsasl_base64_from(key_base64, strlen(key_base64), &key_raw, &key_raw_len);
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
      gpgme_key_release(key);
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
      rexmpp_iq_new(s, "get", jid, fp_req, rexmpp_pgp_fp_reply);
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

void rexmpp_pgp_key_publish_list_iq (rexmpp_t *s,
                                     xmlNodePtr req,
                                     xmlNodePtr response,
                                     int success)
{
  if (! success) {
    rexmpp_log(s, LOG_WARNING, "Failed to publish an OpenpPGP key list");
    return;
  }
  rexmpp_log(s, LOG_INFO, "Published an OpenpPGP key list");
}

void rexmpp_pgp_key_publish_iq (rexmpp_t *s,
                                xmlNodePtr req,
                                xmlNodePtr response,
                                int success)
{
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
  struct tm *utc_time = gmtime(&t);
  strftime(time_str, 42, "%FT%TZ", utc_time);

  xmlNodePtr metadata = xmlNewNode(NULL, "pubkey-metadata");
  xmlNewNs(metadata, "urn:xmpp:openpgp:0", NULL);
  xmlNewProp(metadata, "date", time_str);
  xmlNewProp(metadata, "v4-fingerprint", fingerprint);

  free(node);

  xmlNodePtr fps = rexmpp_published_fingerprints(s, s->assigned_jid.bare);
  if (fps != NULL) {
    metadata->next = xmlCopyNodeList(fps);
  }

  xmlNodePtr keylist = xmlNewNode(NULL, "public-keys-list");
  xmlNewNs(keylist, "urn:xmpp:openpgp:0", NULL);
  xmlAddChild(keylist, metadata);

  xmlNodePtr item = xmlNewNode(NULL, "item");
  xmlNewNs(item, "http://jabber.org/protocol/pubsub", NULL);
  xmlAddChild(item, keylist);

  publish = xmlNewNode(NULL, "publish");
  xmlNewNs(publish, "http://jabber.org/protocol/pubsub", NULL);
  xmlNewProp(publish, "node", "urn:xmpp:openpgp:0:public-keys");
  xmlAddChild(publish, item);

  pubsub = xmlNewNode(NULL, "pubsub");
  xmlNewNs(pubsub, "http://jabber.org/protocol/pubsub", NULL);
  xmlAddChild(pubsub, publish);

  rexmpp_iq_new(s, "set", NULL, pubsub, rexmpp_pgp_key_publish_list_iq);
}


rexmpp_err_t rexmpp_openpgp_publish_key (rexmpp_t *s, const char *fp) {
  if (strlen(fp) != 40) {
    rexmpp_log(s, LOG_ERR, "Wrong fingerprint length: %d", strlen(fp));
    return REXMPP_E_PGP;
  }
  if (rexmpp_openpgp_key_is_published(s, fp)) {
    rexmpp_log(s, LOG_DEBUG, "Key %s is already published", fp);
    return REXMPP_SUCCESS;
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
  err = gpgme_op_export(s->pgp_ctx, fp, GPGME_EXPORT_MODE_MINIMAL, key_dh);
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
  struct tm *utc_time = gmtime(&t);
  strftime(time_str, 42, "%FT%TZ", utc_time);

  xmlNodePtr item = xmlNewNode(NULL, "item");
  xmlNewNs(item, "http://jabber.org/protocol/pubsub", NULL);
  xmlNewProp(item, "id", time_str);
  xmlAddChild(item, pubkey);

  char node_str[72];
  snprintf(node_str, 72, "urn:xmpp:openpgp:0:public-keys:%s", fp);
  xmlNodePtr publish = xmlNewNode(NULL, "publish");
  xmlNewNs(publish, "http://jabber.org/protocol/pubsub", NULL);
  xmlNewProp(publish, "node", node_str);
  xmlAddChild(publish, item);

  xmlNodePtr pubsub = xmlNewNode(NULL, "pubsub");
  xmlNewNs(pubsub, "http://jabber.org/protocol/pubsub", NULL);
  xmlAddChild(pubsub, publish);

  rexmpp_iq_new(s, "set", NULL, pubsub, rexmpp_pgp_key_publish_iq);

  return REXMPP_SUCCESS;
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
  if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
    rexmpp_log(s, LOG_ERR, "Failed to decrypt/verify: %s", gpgme_strerror(err));
    gpgme_data_release(plain_dh);
    return NULL;
  }
  plain = gpgme_data_release_and_get_mem(plain_dh, &plain_len);
  if (plain == NULL) {
    rexmpp_log(s, LOG_ERR, "Failed to release and get memory");
    return NULL;
  }
  xmlNodePtr elem = NULL;
  xmlDocPtr doc = xmlReadMemory(plain, plain_len, "", "utf-8", XML_PARSE_NONET);
  if (doc != NULL) {
    elem = xmlCopyNode(xmlDocGetRootElement(doc), 1);
    xmlFreeDoc(doc);
  } else {
    rexmpp_log(s, LOG_ERR, "Failed to parse an XML document");
  }
  free(plain);
  return elem;
}

void rexmpp_openpgp_add_keys (rexmpp_t *s,
                              char *jid,
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
    err = gpgme_get_key(s->pgp_ctx, fingerprint, &(*keys)[*nkeys], 0);
    if (gpg_err_code(err) == GPG_ERR_NO_ERROR) {
      *nkeys = *nkeys + 1;
      if (*nkeys == *allocated) {
        *allocated = *allocated * 2;
        *keys = realloc(*keys, sizeof(gpgme_key_t *) * *allocated);
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

char *rexmpp_openpgp_encrypt_sign (rexmpp_t *s,
                                   xmlNodePtr payload,
                                   char **recipients)
{
  int i, nkeys = 0, allocated = 8;
  gpgme_error_t err;
  int sasl_err;

  /* A random-length random-content padding. */
  char *rand_str, rand[256];
  gsasl_random(rand, 1);
  size_t rand_str_len = 0, rand_len = (unsigned char)rand[0] % (255 - 16) + 16;
  sasl_err = gsasl_random(rand, rand_len);
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

  /* Locate keys. */
  gpgme_key_t *keys = malloc(sizeof(gpgme_key_t *) * allocated);
  keys[0] = NULL;

  /* Add own keys for encryption and signing. */
  rexmpp_openpgp_add_keys(s, s->initial_jid.bare, &keys, &nkeys, &allocated);
  for (i = 0; i < nkeys; i++) {
    gpgme_signers_add(s->pgp_ctx, keys[i]);
  }
  /* Add recipients' keys for encryption. */
  for (i = 0; recipients[i] != NULL; i++) {
    rexmpp_openpgp_add_keys(s, recipients[i], &keys, &nkeys, &allocated);
  }

  /* Prepare a signcrypt element. */
  xmlNodePtr signcrypt = xmlNewNode(NULL, "signcrypt");
  xmlNewNs(signcrypt, "urn:xmpp:openpgp:0", NULL);

  /* Add all the recipients. */
  for (i = 0; recipients[i] != NULL; i++) {
    xmlNodePtr to = xmlNewNode(NULL, "to");
    xmlNewNs(to, "urn:xmpp:openpgp:0", NULL);
    xmlNewProp(to, "jid", recipients[i]);
    xmlAddChild(signcrypt, to);
  }

  /* Add timestamp. */
  char time_str[42];
  time_t t = time(NULL);
  struct tm *utc_time = gmtime(&t);
  strftime(time_str, 42, "%FT%TZ", utc_time);

  xmlNodePtr time = xmlNewNode(NULL, "time");
  xmlNewNs(time, "urn:xmpp:openpgp:0", NULL);
  xmlNewProp(time, "stamp", time_str);
  xmlAddChild(signcrypt, time);

  xmlNodePtr rpad = xmlNewNode(NULL, "rpad");
  xmlNewNs(rpad, "urn:xmpp:openpgp:0", NULL);
  xmlNodeAddContent(rpad, rand_str);
  free(rand_str);
  xmlAddChild(signcrypt, rpad);

  /* Add the payload. */
  xmlNodePtr pl = xmlNewNode(NULL, "payload");
  xmlNewNs(pl, "urn:xmpp:openpgp:0", NULL);
  xmlAddChild(pl, payload);
  xmlAddChild(signcrypt, pl);

  /* Serialize the resulting XML. */
  char *plaintext = rexmpp_xml_serialize(signcrypt);
  xmlFreeNode(signcrypt);

  /* Encrypt, base64-encode. */
  gpgme_data_t cipher_dh, plain_dh;
  gpgme_data_new(&cipher_dh);
  gpgme_data_new_from_mem(&plain_dh, plaintext, strlen(plaintext), 0);
  err = gpgme_op_encrypt_sign(s->pgp_ctx, keys, GPGME_ENCRYPT_NO_ENCRYPT_TO,
                              plain_dh, cipher_dh);
  for (i = 0; i < nkeys; i++) {
    gpgme_key_release(keys[i]);
  }
  free(keys);
  gpgme_data_release(plain_dh);
  if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
    rexmpp_log(s, LOG_ERR, "Failed to encrypt: %s", gpgme_strerror(err));
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
