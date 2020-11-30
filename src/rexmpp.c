/**
   @file rexmpp.c
   @brief rexmpp, a reusable XMPP IM client library.
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <arpa/nameser.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <libxml/tree.h>
#include <libxml/xmlsave.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/dane.h>
#include <gsasl.h>
#include <unbound.h>
#include <gpgme.h>

#include "rexmpp.h"
#include "rexmpp_tcp.h"
#include "rexmpp_socks.h"
#include "rexmpp_roster.h"
#include "rexmpp_dns.h"
#include "rexmpp_jid.h"
#include "rexmpp_openpgp.h"
#include "rexmpp_console.h"

const char *rexmpp_strerror (rexmpp_err_t error) {
  switch (error) {
  case REXMPP_SUCCESS: return "No error";
  case REXMPP_E_AGAIN: return "An operation is in progress";
  case REXMPP_E_SEND_QUEUE_FULL: return
      "A message can't be queued for sending, because the queue is full";
  case REXMPP_E_STANZA_QUEUE_FULL: return
      "The library can't take responsibility for message delivery because "
      "XEP-0198 stanza queue is full";
  case REXMPP_E_CANCELLED: return "Cancelled by a user";
  case REXMPP_E_SEND_BUFFER_EMPTY: return
      "Attempted to send while send buffer is empty";
  case REXMPP_E_SEND_BUFFER_NOT_EMPTY: return
      "Attempted to start sending while send buffer is not empty";
  case REXMPP_E_SASL: return "SASL-related error";
  case REXMPP_E_PGP: return "OpenPGP-related error";
  case REXMPP_E_TLS: return "TLS-related error";
  case REXMPP_E_TCP: return "TCP-related error";
  case REXMPP_E_DNS: return "DNS-related error";
  case REXMPP_E_XML: return "XML-related error";
  case REXMPP_E_JID: return "JID-related error";
  case REXMPP_E_MALLOC: return "Memory allocation failure";
  case REXMPP_E_ROSTER: return "Roster-related error";
  case REXMPP_E_ROSTER_ITEM_NOT_FOUND: return "Roster item is not found";
  case REXMPP_E_PARAM: return "An erroneous parameter is supplied";
  case REXMPP_E_STREAM: return "A stream error";
  case REXMPP_E_OTHER: return "An unspecified error";
  default: return "Unknown error";
  }
}

void rexmpp_sax_start_elem_ns (rexmpp_t *s,
                               const char *localname,
                               const char *prefix,
                               const char *URI,
                               int nb_namespaces,
                               const char **namespaces,
                               int nb_attributes,
                               int nb_defaulted,
                               const char **attributes);

void rexmpp_sax_end_elem_ns(rexmpp_t *s,
                            const char *localname,
                            const char *prefix,
                            const char *URI);

void rexmpp_sax_characters (rexmpp_t *s, const char * ch, int len);

void rexmpp_log (rexmpp_t *s, int priority, const char *format, ...)
{
  va_list args;
  if (s->log_function != NULL) {
    va_start(args, format);
    s->log_function (s, priority, format, args);
    va_end(args);
  }
}

char *rexmpp_capabilities_string (rexmpp_t *s, xmlNodePtr info) {
  /* Assuming the info is sorted already. Would be better to sort it
     here (todo). */
  xmlNodePtr cur;
  int buf_len = 1024, str_len = 0;
  char *str = malloc(buf_len);
  for (cur = info; cur; cur = cur->next) {
    if (strcmp(cur->name, "identity") == 0) {
      int cur_len = 5;          /* ///< for an empty identity */

      /* Collect the properties we'll need. */
      char *category = xmlGetProp(cur, "category");
      char *type = xmlGetProp(cur, "type");
      char *lang = xmlGetProp(cur, "xml:lang");
      char *name = xmlGetProp(cur, "name");

      /* Calculate the length needed. */
      if (category != NULL) {
        cur_len += strlen(category);
      }
      if (type != NULL) {
        cur_len += strlen(type);
      }
      if (lang != NULL) {
        cur_len += strlen(lang);
      }
      if (name != NULL) {
        cur_len += strlen(name);
      }

      /* Reallocate the buffer if necessary. */
      if (cur_len > buf_len - str_len) {
        while (cur_len > buf_len - str_len) {
          buf_len *= 2;
        }
        str = realloc(str, buf_len);
      }

      /* Fill the data. */
      if (category != NULL) {
        strcpy(str + str_len, category);
        str_len += strlen(category);
      }
      str[str_len] = '/';
      str_len++;
      if (type != NULL) {
        strcpy(str + str_len, type);
        str_len += strlen(type);
      }
      str[str_len] = '/';
      str_len++;
      if (lang != NULL) {
        strcpy(str + str_len, lang);
        str_len += strlen(lang);
      }
      str[str_len] = '/';
      str_len++;
      if (name != NULL) {
        strcpy(str + str_len, name);
        str_len += strlen(name);
      }
      str[str_len] = '<';
      str_len++;

      /* Free the values. */
      if (category != NULL) {
        free(category);
      }
      if (type != NULL) {
        free(type);
      }
      if (lang != NULL) {
        free(lang);
      }
      if (name != NULL) {
        free(name);
      }
    } else if (strcmp(cur->name, "feature") == 0) {
      char *var = xmlGetProp(cur, "var");
      int cur_len = 2 + strlen(var);
      if (cur_len > buf_len - str_len) {
        while (cur_len > buf_len - str_len) {
          buf_len *= 2;
        }
        str = realloc(str, buf_len);
      }
      strcpy(str + str_len, var);
      str_len += strlen(var);
      str[str_len] = '<';
      str_len++;
      free(var);
    } else {
      rexmpp_log(s, LOG_ERR,
                 "Unsupported node type in disco info: %s", cur->name);
    }
  }
  str[str_len] = '\0';
  return str;
}

char *rexmpp_capabilities_hash (rexmpp_t *s,
                                xmlNodePtr info)
{
  int err;
  char *hash;
  char *str = rexmpp_capabilities_string(s, info);
  err = gsasl_sha1(str, strlen(str), &hash);
  free(str);
  if (err) {
    rexmpp_log(s, LOG_ERR, "Hashing failure: %s",
               gsasl_strerror(err));
    return NULL;
  }
  char *out = NULL;
  size_t out_len = 0;
  gsasl_base64_to(hash, 20, &out, &out_len);
  free(hash);
  return out;
}

xmlNodePtr rexmpp_find_event (rexmpp_t *s,
                              const char *from,
                              const char *node,
                              xmlNodePtr *prev_event)
{
  xmlNodePtr prev, cur;
  for (prev = NULL, cur = s->roster_events;
       cur != NULL;
       prev = cur, cur = xmlNextElementSibling(cur)) {
    char *cur_from = xmlGetProp(cur, "from");
    if (cur_from == NULL) {
      continue;
    }
    xmlNodePtr cur_event =
      rexmpp_xml_find_child(cur,
                            "http://jabber.org/protocol/pubsub#event",
                            "event");
    xmlNodePtr cur_items =
      rexmpp_xml_find_child(cur_event,
                            "http://jabber.org/protocol/pubsub#event",
                            "items");
    if (cur_items == NULL) {
      free(cur_from);
      continue;
    }
    char *cur_node = xmlGetProp(cur_items, "node");
    if (cur_node == NULL) {
      continue;
    }
    int match = (strcmp(cur_from, from) == 0 && strcmp(cur_node, node) == 0);
    free(cur_node);
    free(cur_from);
    if (match) {
      if (prev_event != NULL) {
        *prev_event = prev;
      }
      return cur;
    }
  }
  return NULL;
}

char *rexmpp_get_name (rexmpp_t *s, const char *jid_str) {
  struct rexmpp_jid jid;
  if (rexmpp_jid_parse(jid_str, &jid) != 0) {
    return NULL;
  }
  if (s->manage_roster) {
    xmlNodePtr roster_item = rexmpp_roster_find_item(s, jid.bare, NULL);
    if (roster_item) {
      char *name = xmlGetProp(roster_item, "name");
      if (name != NULL) {
        return name;
      }
    }
    if (s->track_roster_events) {
      xmlNodePtr elem =
        rexmpp_find_event(s, jid.bare, "http://jabber.org/protocol/nick", NULL);
      if (elem != NULL) {
        xmlNodePtr event =
          rexmpp_xml_find_child(elem,
                                "http://jabber.org/protocol/pubsub#event",
                                "event");
        xmlNodePtr items =
          rexmpp_xml_find_child(event,
                                "http://jabber.org/protocol/pubsub#event",
                                "items");
        xmlNodePtr item =
          rexmpp_xml_find_child(items,
                                "http://jabber.org/protocol/pubsub#event",
                                "item");
        if (item != NULL) {
          xmlNodePtr nick =
            rexmpp_xml_find_child(item,
                                  "http://jabber.org/protocol/nick",
                                  "nick");
          if (nick != NULL) {
            return xmlNodeGetContent(nick);
          }
        }
      }
    }
  }
  return strdup(jid.bare);
}

xmlNodePtr rexmpp_xml_feature (const char *var) {
  xmlNodePtr feature = xmlNewNode(NULL, "feature");
  xmlNewProp(feature, "var", var);
  return feature;
}

xmlNodePtr rexmpp_xml_error (const char *type, const char *condition) {
  xmlNodePtr error = xmlNewNode(NULL, "error");
  xmlNewProp(error, "type", type);
  xmlNodePtr cond = xmlNewNode(NULL, condition);
  xmlNewNs(cond, "urn:ietf:params:xml:ns:xmpp-stanzas", NULL);
  xmlAddChild(error, cond);
  return error;
}

xmlNodePtr rexmpp_disco_info (rexmpp_t *s) {
  if (s->disco_info != NULL) {
    return s->disco_info;
  }
  xmlNodePtr prev = NULL, cur;
  /* There must be at least one identity, so filling in somewhat
     sensible defaults. A basic client may leave them be, while an
     advanced one would adjust and/or extend them. */
  s->disco_info = xmlNewNode(NULL, "identity");
  xmlNewProp(s->disco_info, "category", "client");
  xmlNewProp(s->disco_info, "type", "console");
  xmlNewProp(s->disco_info, "name", "rexmpp2");
  prev = s->disco_info;
  cur = rexmpp_xml_feature("http://jabber.org/protocol/disco#info");
  prev->next = cur;
  prev = cur;
  if (s->nick_notifications) {
    cur = rexmpp_xml_feature("http://jabber.org/protocol/nick+notify");
    prev->next = cur;
    prev = cur;
  }
  if (s->autojoin_bookmarked_mucs) {
    cur = rexmpp_xml_feature("urn:xmpp:bookmarks:1+notify");
    prev->next = cur;
    prev = cur;
  }
  if (s->retrieve_openpgp_keys) {
    cur = rexmpp_xml_feature("urn:xmpp:openpgp:0:public-keys+notify");
    prev->next = cur;
    prev = cur;
  }
  cur = rexmpp_xml_feature("urn:xmpp:ping");
  prev->next = cur;
  prev = cur;
  return s->disco_info;
}

int rexmpp_sasl_cb (Gsasl *ctx, Gsasl_session *sctx, Gsasl_property prop) {
  (void)sctx;      /* The session should already be in rexmpp_t. */
  rexmpp_t *s = gsasl_callback_hook_get(ctx);
  if (s == NULL || s->sasl_property_cb == NULL) {
    return GSASL_NO_CALLBACK;
  }
  return s->sasl_property_cb(s, prop);
}

rexmpp_err_t rexmpp_init (rexmpp_t *s, const char *jid)
{
  int err;
  xmlSAXHandler sax = {
    .initialized = XML_SAX2_MAGIC,
    .characters = (charactersSAXFunc)rexmpp_sax_characters,
    .startElementNs = (startElementNsSAX2Func)rexmpp_sax_start_elem_ns,
    .endElementNs = (endElementNsSAX2Func)rexmpp_sax_end_elem_ns,
  };

  s->tcp_state = REXMPP_TCP_NONE;
  s->resolver_state = REXMPP_RESOLVER_NONE;
  s->stream_state = REXMPP_STREAM_NONE;
  s->tls_state = REXMPP_TLS_INACTIVE;
  s->sasl_state = REXMPP_SASL_INACTIVE;
  s->sm_state = REXMPP_SM_INACTIVE;
  s->carbons_state = REXMPP_CARBONS_INACTIVE;
  s->manual_host = NULL;
  s->manual_port = 5222;
  s->manual_direct_tls = 0;
  s->disco_node = "rexmpp";
  s->socks_host = NULL;
  s->server_host = NULL;
  s->enable_carbons = 1;
  s->enable_service_discovery = 1;
  s->manage_roster = 1;
  s->roster_cache_file = NULL;
  s->track_roster_presence = 1;
  s->track_roster_events = 1;
  s->nick_notifications = 1;
  s->retrieve_openpgp_keys = 1;
  s->autojoin_bookmarked_mucs = 1;
  s->send_buffer = NULL;
  s->send_queue = NULL;
  s->resolver_ctx = NULL;
  s->server_srv = NULL;
  s->server_srv_cur = -1;
  s->server_srv_tls = NULL;
  s->server_srv_tls_cur = -1;
  s->server_socket = -1;
  s->current_element_root = NULL;
  s->current_element = NULL;
  s->input_queue = NULL;
  s->input_queue_last = NULL;
  s->stream_features = NULL;
  s->roster_items = NULL;
  s->roster_ver = NULL;
  s->roster_presence = NULL;
  s->roster_events = NULL;
  s->stanza_queue = NULL;
  s->stream_id = NULL;
  s->active_iq = NULL;
  s->tls_session_data = NULL;
  s->tls_session_data_size = 0;
  s->reconnect_number = 0;
  s->next_reconnect_time.tv_sec = 0;
  s->next_reconnect_time.tv_usec = 0;
  s->initial_jid.full[0] = '\0';
  s->assigned_jid.full[0] = '\0';
  s->stanza_queue_size = 1024;
  s->send_queue_size = 1024;
  s->iq_queue_size = 1024;
  s->log_function = NULL;
  s->sasl_property_cb = NULL;
  s->xml_in_cb = NULL;
  s->xml_out_cb = NULL;
  s->roster_modify_cb = NULL;
  s->console_print_cb = NULL;
  s->ping_delay = 600;
  s->ping_requested = 0;
  s->last_network_activity = 0;
  s->disco_info = NULL;

  if (jid == NULL) {
    rexmpp_log(s, LOG_CRIT, "No initial JID is provided.");
    return REXMPP_E_JID;
  }

  if (rexmpp_jid_parse(jid, &(s->initial_jid))) {
    rexmpp_log(s, LOG_CRIT, "Failed to parse the initial JID.");
    return REXMPP_E_JID;
  }

  s->xml_parser = xmlCreatePushParserCtxt(&sax, s, "", 0, NULL);

  if (s->xml_parser == NULL) {
    rexmpp_log(s, LOG_CRIT, "Failed to create an XML parser context.");
    return REXMPP_E_XML;
  }

  s->resolver_ctx = ub_ctx_create();
  if (s->resolver_ctx == NULL) {
    rexmpp_log(s, LOG_CRIT, "Failed to create resolver context");
    xmlFreeParserCtxt(s->xml_parser);
    return REXMPP_E_DNS;
  }
  err = ub_ctx_resolvconf(s->resolver_ctx, NULL);
  if (err != 0) {
    rexmpp_log(s, LOG_WARNING, "Failed to read resolv.conf: %s",
               ub_strerror(err));
  }
  err = ub_ctx_hosts(s->resolver_ctx, NULL);
  if (err != 0) {
    rexmpp_log(s, LOG_WARNING, "Failed to read hosts file: %s",
               ub_strerror(err));
  }
  /* todo: better to make this path configurable, not to hardcode it */
  err = ub_ctx_trustedkeys(s->resolver_ctx, "/etc/unbound/root.key");
  if (err != 0) {
    rexmpp_log(s, LOG_WARNING, "Failed to set root key file for DNSSEC: %s",
               ub_strerror(err));
  }

  err = gnutls_certificate_allocate_credentials(&(s->gnutls_cred));
  if (err) {
    rexmpp_log(s, LOG_CRIT, "gnutls credentials allocation error: %s",
               gnutls_strerror(err));
    xmlFreeParserCtxt(s->xml_parser);
    return REXMPP_E_TLS;
  }
  err = gnutls_certificate_set_x509_system_trust(s->gnutls_cred);
  if (err < 0) {
    rexmpp_log(s, LOG_CRIT, "Certificates loading error: %s",
               gnutls_strerror(err));
    xmlFreeParserCtxt(s->xml_parser);
    return REXMPP_E_TLS;
  }

  err = gsasl_init(&(s->sasl_ctx));
  if (err) {
    rexmpp_log(s, LOG_CRIT, "gsasl initialisation error: %s",
               gsasl_strerror(err));
    gnutls_certificate_free_credentials(s->gnutls_cred);
    xmlFreeParserCtxt(s->xml_parser);
    return REXMPP_E_SASL;
  }
  gsasl_callback_hook_set(s->sasl_ctx, s);
  gsasl_callback_set(s->sasl_ctx, rexmpp_sasl_cb);

  gpgme_check_version(NULL);
  err = gpgme_new(&(s->pgp_ctx));
  if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
    rexmpp_log(s, LOG_CRIT, "gpgme initialisation error: %s",
               gpgme_strerror(err));
    gsasl_done(s->sasl_ctx);
    gnutls_certificate_free_credentials(s->gnutls_cred);
    xmlFreeParserCtxt(s->xml_parser);
    return REXMPP_E_PGP;
  }

  return REXMPP_SUCCESS;
}

/* Prepares for a reconnect: cleans up some things (e.g., SASL and TLS
   structures), but keeps others (e.g., stanza queue and stream ID,
   since we may resume the stream afterwards). */
void rexmpp_cleanup (rexmpp_t *s) {
  if (s->tls_state != REXMPP_TLS_INACTIVE &&
      s->tls_state != REXMPP_TLS_AWAITING_DIRECT) {
    gnutls_deinit(s->gnutls_session);
  }
  s->tls_state = REXMPP_TLS_INACTIVE;
  if (s->sasl_state != REXMPP_SASL_INACTIVE) {
    gsasl_finish(s->sasl_session);
    s->sasl_session = NULL;
    s->sasl_state = REXMPP_SASL_INACTIVE;
  }
  if (s->tcp_state == REXMPP_TCP_CONNECTING) {
    int sock = rexmpp_tcp_conn_finish(&s->server_connection);
    if (sock != -1) {
      close(sock);
    }
    s->tcp_state = REXMPP_TCP_NONE;
  }
  if (s->server_socket != -1) {
    close(s->server_socket);
    s->server_socket = -1;
    s->tcp_state = REXMPP_TCP_NONE;
  }
  if (s->send_buffer != NULL) {
    free(s->send_buffer);
    s->send_buffer = NULL;
  }
  if (s->stream_features != NULL) {
    xmlFreeNode(s->stream_features);
    s->stream_features = NULL;
  }
  if (s->send_queue != NULL) {
    xmlFreeNodeList(s->send_queue);
    s->send_queue = NULL;
  }
  if (s->current_element_root != NULL) {
    xmlFreeNode(s->current_element_root);
    s->current_element_root = NULL;
    s->current_element = NULL;
  }
  if (s->input_queue != NULL) {
    xmlFreeNodeList(s->input_queue);
    s->input_queue = NULL;
    s->input_queue_last = NULL;
  }
  if (s->server_srv != NULL) {
    ub_resolve_free(s->server_srv);
    s->server_srv = NULL;
    s->server_srv_cur = -1;
  }
  if (s->server_srv_tls != NULL) {
    ub_resolve_free(s->server_srv_tls);
    s->server_srv_tls = NULL;
    s->server_srv_tls_cur = -1;
  }
  s->sm_state = REXMPP_SM_INACTIVE;
  s->ping_requested = 0;
}

/* Frees the things that persist through reconnects. */
void rexmpp_done (rexmpp_t *s) {
  rexmpp_cleanup(s);
  gpgme_release(s->pgp_ctx);
  gsasl_done(s->sasl_ctx);
  gnutls_certificate_free_credentials(s->gnutls_cred);
  if (s->resolver_ctx != NULL) {
    ub_ctx_delete(s->resolver_ctx);
    s->resolver_ctx = NULL;
  }
  xmlFreeParserCtxt(s->xml_parser);
  if (s->stream_id != NULL) {
    free(s->stream_id);
    s->stream_id = NULL;
  }
  if (s->roster_items != NULL) {
    xmlFreeNodeList(s->roster_items);
    s->roster_items = NULL;
  }
  if (s->roster_presence != NULL) {
    xmlFreeNodeList(s->roster_presence);
    s->roster_presence = NULL;
  }
  if (s->roster_events != NULL) {
    xmlFreeNodeList(s->roster_events);
    s->roster_events = NULL;
  }
  if (s->roster_ver != NULL) {
    free(s->roster_ver);
    s->roster_ver = NULL;
  }
  if (s->disco_info != NULL) {
    xmlFreeNodeList(s->disco_info);
    s->disco_info = NULL;
  }
  if (s->stanza_queue != NULL) {
    xmlFreeNodeList(s->stanza_queue);
    s->stanza_queue = NULL;
  }
  while (s->active_iq != NULL) {
    rexmpp_iq_t *next = s->active_iq->next;
    xmlFreeNode(s->active_iq->request);
    free(s->active_iq);
    s->active_iq = next;
  }
  if (s->tls_session_data != NULL) {
    free(s->tls_session_data);
  }
}

void rexmpp_schedule_reconnect (rexmpp_t *s) {
  if (s->reconnect_number == 0) {
    gnutls_rnd(GNUTLS_RND_NONCE, &s->reconnect_seconds, sizeof(time_t));
    if (s->reconnect_seconds < 0) {
      s->reconnect_seconds = - s->reconnect_seconds;
    }
    s->reconnect_seconds %= 60;
  }
  time_t seconds = 3600;
  if (s->reconnect_number <= 12) {
    seconds = s->reconnect_seconds << s->reconnect_number;
  }
  if (seconds > 3600) {
    seconds = 3600;
  }
  gettimeofday(&(s->next_reconnect_time), NULL);
  s->next_reconnect_time.tv_sec += seconds;
  rexmpp_log(s, LOG_DEBUG, "Scheduled reconnect number %d, in %d seconds",
             s->reconnect_number,
             seconds);
  s->reconnect_number++;
}


const char *jid_bare_to_host (const char *jid_bare) {
  char *jid_host;
  jid_host = strchr(jid_bare, '@');
  if (jid_host != NULL) {
    return jid_host + 1;
  }
  return NULL;
}

xmlNodePtr rexmpp_xml_add_id (rexmpp_t *s, xmlNodePtr node) {
  int sasl_err;
  char buf_raw[18], *buf_base64 = NULL;
  size_t buf_base64_len = 0;
  sasl_err = gsasl_nonce(buf_raw, 18);
  if (sasl_err != GSASL_OK) {
    rexmpp_log(s, LOG_ERR, "Random generation failure: %s",
               gsasl_strerror(sasl_err));
    return NULL;
  }
  sasl_err = gsasl_base64_to(buf_raw, 18, &buf_base64, &buf_base64_len);
  if (sasl_err != GSASL_OK) {
    rexmpp_log(s, LOG_ERR, "Base-64 encoding failure: %s",
               gsasl_strerror(sasl_err));
    return NULL;
  }
  xmlNewProp(node, "id", buf_base64);
  free(buf_base64);
  return node;
}

unsigned int rexmpp_xml_siblings_count (xmlNodePtr node) {
  unsigned int i;
  for (i = 0; node != NULL; i++) {
    node = xmlNextElementSibling(node);
  }
  return i;
}

int rexmpp_xml_match (xmlNodePtr node,
                      const char *namespace,
                      const char *name)
{
  if (node == NULL) {
    return 0;
  }
  if (name != NULL) {
    if (strcmp(name, node->name) != 0) {
      return 0;
    }
  }
  if (namespace != NULL) {
    if (node->ns == NULL) {
      if (strcmp(namespace, "jabber:client") != 0) {
        return 0;
      }
    } else {
      if (strcmp(namespace, node->ns->href) != 0) {
        return 0;
      }
    }
  }
  return 1;
}

xmlNodePtr rexmpp_xml_find_child (xmlNodePtr node,
                                  const char *namespace,
                                  const char *name)
{
  if (node == NULL) {
    return NULL;
  }
  xmlNodePtr child;
  for (child = xmlFirstElementChild(node);
       child != NULL;
       child = xmlNextElementSibling(child))
    {
      if (rexmpp_xml_match(child, namespace, name)) {
        return child;
      }
    }
  return NULL;
}

xmlNodePtr rexmpp_xml_set_delay (rexmpp_t *s, xmlNodePtr node) {
  if (rexmpp_xml_find_child (node, NULL, "delay")) {
    return node;
  }
  char buf[42];
  time_t t = time(NULL);
  struct tm utc_time;
  gmtime_r(&t, &utc_time);
  strftime(buf, 42, "%FT%TZ", &utc_time);
  xmlNodePtr delay = xmlNewChild(node, NULL, "delay", NULL);
  xmlNewProp(delay, "stamp", buf);
  if (s != NULL && s->assigned_jid.full[0]) {
    xmlNewProp(delay, "from", s->assigned_jid.full);
  }
  return node;
}

xmlNodePtr rexmpp_xml_parse (const char *str, int str_len) {
  xmlNodePtr elem = NULL;
  xmlDocPtr doc = xmlReadMemory(str, str_len, "", "utf-8", XML_PARSE_NONET);
  if (doc != NULL) {
    elem = xmlCopyNode(xmlDocGetRootElement(doc), 1);
    xmlFreeDoc(doc);
  }
  return elem;
}

char *rexmpp_xml_serialize (xmlNodePtr node) {
  xmlBufferPtr buf = xmlBufferCreate();
  xmlSaveCtxtPtr ctx = xmlSaveToBuffer(buf, "utf-8", 0);
  xmlSaveTree(ctx, node);
  xmlSaveFlush(ctx);
  xmlSaveClose(ctx);
  unsigned char *out = xmlBufferDetach(buf);
  xmlBufferFree(buf);
  return out;
}

int rexmpp_xml_is_stanza (xmlNodePtr node) {
  return rexmpp_xml_match(node, "jabber:client", "message") ||
    rexmpp_xml_match(node, "jabber:client", "iq") ||
    rexmpp_xml_match(node, "jabber:client", "presence");
}


rexmpp_err_t rexmpp_send_start (rexmpp_t *s, const void *data, size_t data_len)
{
  int sasl_err;
  if (s->send_buffer != NULL) {
    rexmpp_log(s, LOG_CRIT, "send buffer is not empty: %s", s->send_buffer);
    return REXMPP_E_SEND_BUFFER_NOT_EMPTY;
  }
  if (s->sasl_state == REXMPP_SASL_ACTIVE) {
    sasl_err = gsasl_encode (s->sasl_session, data, data_len,
                             &(s->send_buffer), &(s->send_buffer_len));
    if (sasl_err != GSASL_OK) {
      rexmpp_log(s, LOG_ERR, "SASL encoding error: %s",
                 gsasl_strerror(sasl_err));
      s->sasl_state = REXMPP_SASL_ERROR;
      return REXMPP_E_SASL;
    }
  } else {
    s->send_buffer = malloc(data_len);
    if (s->send_buffer == NULL) {
      return REXMPP_E_MALLOC;
    }
    memcpy(s->send_buffer, data, data_len);
    s->send_buffer_len = data_len;
  }
  s->send_buffer_sent = 0;
  return REXMPP_SUCCESS;
}

rexmpp_err_t rexmpp_send_continue (rexmpp_t *s)
{
  if (s->send_buffer == NULL) {
    rexmpp_log(s, LOG_ERR, "nothing to send");
    return REXMPP_E_SEND_BUFFER_EMPTY;
  }
  int ret;
  while (1) {
    if (s->tls_state == REXMPP_TLS_ACTIVE) {
      ret = gnutls_record_send (s->gnutls_session,
                                s->send_buffer,
                                s->send_buffer_len);
    } else {
      ret = send (s->server_socket,
                  s->send_buffer + s->send_buffer_sent,
                  s->send_buffer_len - s->send_buffer_sent,
                  0);
    }
    if (ret > 0) {
      s->last_network_activity = time(NULL);
      s->send_buffer_sent += ret;
      if (s->send_buffer_sent == s->send_buffer_len) {
        free(s->send_buffer);
        s->send_buffer = NULL;
        if (s->send_queue != NULL) {
          xmlNodePtr node = s->send_queue;
          unsigned char *buf = rexmpp_xml_serialize(node);
          ret = rexmpp_send_start(s, buf, strlen(buf));
          free(buf);
          if (ret != REXMPP_SUCCESS) {
            return ret;
          }
          s->send_queue = xmlNextElementSibling(s->send_queue);
          xmlFreeNode(node);
        } else {
          return REXMPP_SUCCESS;
        }
      }
    } else {
      if (s->tls_state == REXMPP_TLS_ACTIVE) {
        if (ret != GNUTLS_E_AGAIN) {
          s->tls_state = REXMPP_TLS_ERROR;
          /* Assume a TCP error for now as well. */
          rexmpp_log(s, LOG_ERR, "TLS send error: %s", gnutls_strerror(ret));
          rexmpp_cleanup(s);
          s->tcp_state = REXMPP_TCP_ERROR;
          rexmpp_schedule_reconnect(s);
          return REXMPP_E_TLS;
        }
      } else {
        if (errno != EAGAIN) {
          rexmpp_log(s, LOG_ERR, "TCP send error: %s", strerror(errno));
          rexmpp_cleanup(s);
          s->tcp_state = REXMPP_TCP_ERROR;
          rexmpp_schedule_reconnect(s);
          return REXMPP_E_TCP;
        }
      }
      return REXMPP_E_AGAIN;
    }
  }
}

rexmpp_err_t rexmpp_send_raw (rexmpp_t *s, const void *data, size_t data_len)
{
  int ret = rexmpp_send_start(s, data, data_len);
  if (ret == REXMPP_SUCCESS) {
    ret = rexmpp_send_continue(s);
  }
  return ret;
}

rexmpp_err_t rexmpp_sm_send_req (rexmpp_t *s);

rexmpp_err_t rexmpp_send (rexmpp_t *s, xmlNodePtr node)
{
  int need_ack = 0;
  int ret;

  if (s->xml_out_cb != NULL && s->xml_out_cb(s, node) == 1) {
    xmlFreeNode(node);
    rexmpp_log(s, LOG_WARNING, "Message sending was cancelled by xml_out_cb.");
    return REXMPP_E_CANCELLED;
  }

  if (rexmpp_xml_siblings_count(s->send_queue) >= s->send_queue_size) {
    xmlFreeNode(node);
    rexmpp_log(s, LOG_ERR, "The send queue is full, not sending.");
    return REXMPP_E_SEND_QUEUE_FULL;
  }

  rexmpp_console_on_send(s, node);

  if (rexmpp_xml_is_stanza(node)) {
    if (s->sm_state == REXMPP_SM_ACTIVE) {
      if (s->stanzas_out_count - s->stanzas_out_acknowledged >=
          s->stanza_queue_size) {
        xmlFreeNode(node);
        rexmpp_log(s, LOG_ERR, "The stanza queue is full, not sending.");
        return REXMPP_E_STANZA_QUEUE_FULL;
      }
      need_ack = 1;
      xmlNodePtr queued_stanza = rexmpp_xml_set_delay(s, xmlCopyNode(node, 1));
      if (s->stanza_queue == NULL) {
        s->stanza_queue = queued_stanza;
      } else {
        xmlNodePtr last = s->stanza_queue;
        while (xmlNextElementSibling(last) != NULL) {
          last = xmlNextElementSibling(last);
        }
        xmlAddNextSibling(last, queued_stanza);
      }
    }
    if (s->sm_state != REXMPP_SM_INACTIVE) {
      s->stanzas_out_count++;
    }
  }

  if (s->send_buffer == NULL) {
    unsigned char *buf = rexmpp_xml_serialize(node);
    ret = rexmpp_send_raw(s, buf, strlen(buf));
    free(buf);
    xmlFreeNode(node);
    if (ret != REXMPP_SUCCESS && ret != REXMPP_E_AGAIN) {
      return ret;
    }
  } else {
    if (s->send_queue == NULL) {
      s->send_queue = node;
    } else {
      xmlNodePtr last = s->send_queue;
      while (xmlNextElementSibling(last) != NULL) {
        last = xmlNextElementSibling(last);
      }
      xmlAddNextSibling(last, node);
    }
    ret = REXMPP_E_AGAIN;
  }
  if (need_ack) {
    return rexmpp_sm_send_req(s);
  }
  return ret;
}

void rexmpp_iq_reply (rexmpp_t *s,
                      xmlNodePtr req,
                      const char *type,
                      xmlNodePtr payload)
{
  xmlNodePtr iq_stanza = xmlNewNode(NULL, "iq");
  xmlNewNs(iq_stanza, "jabber:client", NULL);
  xmlNewProp(iq_stanza, "type", type);
  char *id = xmlGetProp(req, "id");
  if (id != NULL) {
    xmlNewProp(iq_stanza, "id", id);
    free(id);
  }
  char *to = xmlGetProp(req, "from");
  if (to != NULL) {
    xmlNewProp(iq_stanza, "to", to);
    free(to);
  }
  if (s->assigned_jid.full[0]) {
    xmlNewProp(iq_stanza, "from", s->assigned_jid.full);
  }
  if (payload != NULL) {
    xmlAddChild(iq_stanza, payload);
  }
  rexmpp_send(s, iq_stanza);
}

rexmpp_err_t rexmpp_iq_new (rexmpp_t *s,
                            const char *type,
                            const char *to,
                            xmlNodePtr payload,
                            rexmpp_iq_callback_t cb)
{
  unsigned int i;
  rexmpp_iq_t *prev = NULL, *last = s->active_iq;
  for (i = 0; last != NULL && last->next != NULL; i++) {
    prev = last;
    last = last->next;
  }
  if (i >= s->iq_queue_size && s->iq_queue_size > 0) {
    rexmpp_log(s, LOG_WARNING,
               "The IQ queue limit is reached, giving up on the oldest IQ.");
    prev->next = NULL;
    if (last->cb != NULL) {
      last->cb(s, last->request, NULL, 0);
    }
    xmlFreeNode(last->request);
    free(last);
  }

  xmlNodePtr iq_stanza = rexmpp_xml_add_id(s, xmlNewNode(NULL, "iq"));
  xmlNewNs(iq_stanza, "jabber:client", NULL);
  xmlNewProp(iq_stanza, "type", type);
  if (to != NULL) {
    xmlNewProp(iq_stanza, "to", to);
  }
  if (s->assigned_jid.full[0]) {
    xmlNewProp(iq_stanza, "from", s->assigned_jid.full);
  }
  xmlAddChild(iq_stanza, payload);
  rexmpp_iq_t *iq = malloc(sizeof(rexmpp_iq_t));
  iq->request = xmlCopyNode(iq_stanza, 1);
  iq->cb = cb;
  iq->next = s->active_iq;
  s->active_iq = iq;
  return rexmpp_send(s, iq_stanza);
}

rexmpp_err_t rexmpp_sm_ack (rexmpp_t *s) {
  char buf[11];
  xmlNodePtr ack = xmlNewNode(NULL, "a");
  xmlNewNs(ack, "urn:xmpp:sm:3", NULL);
  snprintf(buf, 11, "%u", s->stanzas_in_count);
  xmlNewProp(ack, "h", buf);
  return rexmpp_send(s, ack);
}

rexmpp_err_t rexmpp_sm_send_req (rexmpp_t *s) {
  xmlNodePtr ack = xmlNewNode(NULL, "r");
  xmlNewNs(ack, "urn:xmpp:sm:3", NULL);
  return rexmpp_send(s, ack);
}

rexmpp_err_t rexmpp_process_element (rexmpp_t *s, xmlNodePtr elem);

rexmpp_err_t rexmpp_recv (rexmpp_t *s) {
  char chunk_raw[4096], *chunk;
  ssize_t chunk_raw_len, chunk_len;
  int sasl_err;
  rexmpp_err_t err = REXMPP_SUCCESS;
  /* Loop here in order to consume data from TLS buffers, which
     wouldn't show up on select(). */
  do {
    if (s->tls_state == REXMPP_TLS_ACTIVE) {
      chunk_raw_len = gnutls_record_recv(s->gnutls_session, chunk_raw, 4096);
    } else {
      chunk_raw_len = recv(s->server_socket, chunk_raw, 4096, 0);
    }
    if (chunk_raw_len > 0) {
      s->last_network_activity = time(NULL);
      if (s->sasl_state == REXMPP_SASL_ACTIVE) {
        sasl_err = gsasl_decode(s->sasl_session, chunk_raw, chunk_raw_len,
                                &chunk, &chunk_len);
        if (sasl_err != GSASL_OK) {
          rexmpp_log(s, LOG_ERR, "SASL decoding error: %s",
                     gsasl_strerror(sasl_err));
          s->sasl_state = REXMPP_SASL_ERROR;
          return REXMPP_E_SASL;
        }
      } else {
        chunk = chunk_raw;
        chunk_len = chunk_raw_len;
      }
      xmlParseChunk(s->xml_parser, chunk, chunk_len, 0);

      xmlNodePtr elem;
      for (elem = s->input_queue;
           /* Skipping everything after an error. Might be better to
              process it anyway, but it could lead to more errors if
              the processing isn't done carefully. */
           elem != NULL && (err == REXMPP_SUCCESS || err == REXMPP_E_AGAIN);
           elem = elem->next)
        {
          if (s->xml_in_cb != NULL && s->xml_in_cb(s, elem) != 0) {
            rexmpp_log(s, LOG_WARNING,
                       "Message processing was cancelled by xml_in_cb.");
          } else {
            err = rexmpp_process_element(s, elem);
          }
        }
      xmlFreeNodeList(s->input_queue);
      s->input_queue = NULL;
      s->input_queue_last = NULL;
      if (err != REXMPP_SUCCESS && err != REXMPP_E_AGAIN) {
        return err;
      }
    } else if (chunk_raw_len == 0) {
      if (s->tls_state == REXMPP_TLS_ACTIVE) {
        s->tls_state = REXMPP_TLS_CLOSED;
        rexmpp_log(s, LOG_INFO, "TLS disconnected");
      }
      rexmpp_log(s, LOG_INFO, "TCP disconnected");
      rexmpp_cleanup(s);
      if (s->stream_state == REXMPP_STREAM_READY ||
          s->stream_state == REXMPP_STREAM_ERROR_RECONNECT) {
        s->tcp_state = REXMPP_TCP_NONE;
        rexmpp_schedule_reconnect(s);
      } else {
        s->tcp_state = REXMPP_TCP_CLOSED;
      }
    } else {
      if (s->tls_state == REXMPP_TLS_ACTIVE) {
        if (chunk_raw_len != GNUTLS_E_AGAIN) {
          s->tls_state = REXMPP_TLS_ERROR;
          /* Assume a TCP error for now as well. */
          rexmpp_log(s, LOG_ERR, "TLS recv error: %s",
                     gnutls_strerror(chunk_raw_len));
          rexmpp_cleanup(s);
          s->tcp_state = REXMPP_TCP_ERROR;
          rexmpp_schedule_reconnect(s);
        }
      } else if (errno != EAGAIN) {
        rexmpp_log(s, LOG_ERR, "TCP recv error: %s", strerror(errno));
        rexmpp_cleanup(s);
        s->tcp_state = REXMPP_TCP_ERROR;
        rexmpp_schedule_reconnect(s);
      }
    }
  } while (chunk_raw_len > 0 && s->tcp_state == REXMPP_TCP_CONNECTED);
  return err;
}

rexmpp_err_t rexmpp_stream_open (rexmpp_t *s) {
  char buf[2048];
  snprintf(buf, 2048,
           "<?xml version='1.0'?>\n"
           "<stream:stream to='%s' version='1.0' "
           "xml:lang='en' xmlns='jabber:client' "
           "xmlns:stream='http://etherx.jabber.org/streams'>",
           s->initial_jid.domain);
  s->stream_state = REXMPP_STREAM_OPENING;
  return rexmpp_send_raw(s, buf, strlen(buf));
}

rexmpp_err_t
rexmpp_process_conn_err (rexmpp_t *s, enum rexmpp_tcp_conn_error err);

rexmpp_err_t rexmpp_start_connecting (rexmpp_t *s) {
  if (s->socks_host == NULL) {
    rexmpp_log(s, LOG_DEBUG, "Connecting to %s:%u",
               s->server_host, s->server_port);
    return
      rexmpp_process_conn_err(s,
                              rexmpp_tcp_conn_init(&s->server_connection,
                                                   s->resolver_ctx,
                                                   s->server_host,
                                                   s->server_port));
  } else {
    rexmpp_log(s, LOG_DEBUG, "Connecting to %s:%u via %s:%u",
               s->server_host, s->server_port,
               s->socks_host, s->socks_port);
    return rexmpp_process_conn_err(s,
                                   rexmpp_tcp_conn_init(&s->server_connection,
                                                        s->resolver_ctx,
                                                        s->socks_host,
                                                        s->socks_port));
  }
}

rexmpp_err_t rexmpp_try_next_host (rexmpp_t *s) {
  struct ub_result *cur_result;
  int cur_number;
  /* todo: check priorities and weights */
  s->tls_state = REXMPP_TLS_INACTIVE;
  if (s->server_srv_tls != NULL && s->server_srv_tls_cur == -1) {
    /* We have xmpps-client records available, but haven't tried any
       of them yet. */
    s->server_srv_tls_cur = 0;
    cur_result = s->server_srv_tls;
    cur_number = s->server_srv_tls_cur;
    s->tls_state = REXMPP_TLS_AWAITING_DIRECT;
  } else if (s->server_srv_tls_cur != -1 &&
             s->server_srv_tls->data[s->server_srv_tls_cur + 1] != NULL) {
    /* We have tried some xmpps-client records, but there is more. */
    s->server_srv_tls_cur++;
    cur_result = s->server_srv_tls;
    cur_number = s->server_srv_tls_cur;
    s->tls_state = REXMPP_TLS_AWAITING_DIRECT;
  } else if (s->server_srv != NULL && s->server_srv_cur == -1) {
    /* Starting with xmpp-client records. */
    s->server_srv_cur = 0;
    cur_result = s->server_srv;
    cur_number = s->server_srv_cur;
  } else if (s->server_srv_cur != -1 &&
             s->server_srv->data[s->server_srv_cur + 1] != NULL) {
    /* Advancing in xmpp-client records. */
    s->server_srv_cur++;
    cur_result = s->server_srv;
    cur_number = s->server_srv_cur;
  } else {
    /* No candidate records left to try. Schedule a reconnect. */
    rexmpp_log(s, LOG_DEBUG,
               "No candidate hosts left to try, scheduling a reconnect");
    rexmpp_cleanup(s);
    rexmpp_schedule_reconnect(s);
    return REXMPP_E_AGAIN;
  }

  int err = rexmpp_parse_srv(cur_result->data[cur_number],
                             cur_result->len[cur_number],
                             &(s->server_active_srv));
  if (err) {
    rexmpp_log(s, LOG_ERR, "Failed to parse an SRV record");
    rexmpp_cleanup(s);
    rexmpp_schedule_reconnect(s);
    return REXMPP_E_DNS;
  }
  s->server_host = s->server_active_srv.target;
  s->server_port = s->server_active_srv.port;
  return rexmpp_start_connecting(s);
}

rexmpp_err_t rexmpp_tls_handshake (rexmpp_t *s) {
  s->tls_state = REXMPP_TLS_HANDSHAKE;
  int ret = gnutls_handshake(s->gnutls_session);
  if (ret == GNUTLS_E_AGAIN) {
    rexmpp_log(s, LOG_DEBUG, "Waiting for TLS handshake to complete");
    return REXMPP_E_AGAIN;
  } else if (ret == 0) {
    int status;

    int srv_is_secure = 0;
    if (s->stream_state == REXMPP_STREAM_NONE &&
        s->server_srv_tls != NULL) { /* Direct TLS */
      srv_is_secure = s->server_srv_tls->secure;
    } else if (s->stream_state != REXMPP_STREAM_NONE &&
               s->server_srv != NULL) { /* STARTTLS connection */
      srv_is_secure = s->server_srv->secure;
    }

    /* Check DANE TLSA records; experimental and purely informative
       now, but may be nice to (optionally) rely on it in the
       future. */
    if ((srv_is_secure || s->manual_host != NULL) &&
        s->server_socket_dns_secure) {
      /* Apparently GnuTLS only checks against the target
         server/derived host, while another possibility is a
         service/source host
         (<https://tools.ietf.org/html/rfc7712#section-5.1>,
         <https://tools.ietf.org/html/rfc7673#section-6>). */
      ret = dane_verify_session_crt(NULL, s->gnutls_session, s->server_host,
                                    "tcp", s->server_port, 0, 0, &status);
      if (ret) {
        rexmpp_log(s, LOG_WARNING, "DANE verification error: %s",
                   dane_strerror(ret));
      } else if (status) {
        if (status & DANE_VERIFY_CA_CONSTRAINTS_VIOLATED) {
          rexmpp_log(s, LOG_WARNING, "The CA constraints were violated");
        }
        if (status & DANE_VERIFY_CERT_DIFFERS) {
          rexmpp_log(s, LOG_WARNING, "The certificate obtained via DNS differs");
        }
        if (status & DANE_VERIFY_UNKNOWN_DANE_INFO) {
          rexmpp_log(s, LOG_WARNING,
                     "No known DANE data was found in the DNS record");
        }
      } else {
        rexmpp_log(s, LOG_INFO,
                   "DANE verification did not reject the certificate");
      }
    }

    ret = gnutls_certificate_verify_peers3(s->gnutls_session,
                                           s->initial_jid.domain,
                                           &status);
    if (ret || status) {
      s->tls_state = REXMPP_TLS_ERROR;
      if (ret) {
        rexmpp_log(s, LOG_ERR, "Certificate parsing error: %s",
                   gnutls_strerror(ret));
      } else if (status & GNUTLS_CERT_UNEXPECTED_OWNER) {
        rexmpp_log(s, LOG_ERR, "Unexpected certificate owner");
      } else {
        rexmpp_log(s, LOG_ERR, "Untrusted certificate");
      }
      gnutls_bye(s->gnutls_session, GNUTLS_SHUT_RDWR);
      rexmpp_cleanup(s);
      rexmpp_schedule_reconnect(s);
      return REXMPP_E_TLS;
    }
    s->tls_state = REXMPP_TLS_ACTIVE;
    rexmpp_log(s, LOG_DEBUG, "TLS ready");

    if (gnutls_session_is_resumed(s->gnutls_session)) {
      rexmpp_log(s, LOG_INFO, "TLS session is resumed");
    } else {
      if (s->tls_session_data != NULL) {
        rexmpp_log(s, LOG_DEBUG, "TLS session is not resumed");
        free(s->tls_session_data);
        s->tls_session_data = NULL;
      }
      gnutls_session_get_data(s->gnutls_session, NULL,
                              &s->tls_session_data_size);
      s->tls_session_data = malloc(s->tls_session_data_size);
      ret = gnutls_session_get_data(s->gnutls_session, s->tls_session_data,
                                    &s->tls_session_data_size);
      if (ret != GNUTLS_E_SUCCESS) {
        rexmpp_log(s, LOG_ERR, "Failed to get TLS session data: %s",
                   gnutls_strerror(ret));
        return REXMPP_E_TLS;
      }
    }

    if (s->stream_state == REXMPP_STREAM_NONE) {
      /* It's a direct TLS connection, so open a stream after
         connecting. */
      return rexmpp_stream_open(s);
    } else {
      /* A STARTTLS connection, restart the stream. */
      xmlCtxtResetPush(s->xml_parser, "", 0, "", "utf-8");
      return rexmpp_stream_open(s);
    }
  } else {
    rexmpp_log(s, LOG_ERR, "Unexpected TLS handshake error: %s",
               gnutls_strerror(ret));
    rexmpp_cleanup(s);
    rexmpp_schedule_reconnect(s);
    return REXMPP_E_TLS;
  }
}

rexmpp_err_t rexmpp_tls_start (rexmpp_t *s) {
  gnutls_datum_t xmpp_client_protocol = {"xmpp-client", strlen("xmpp-client")};
  rexmpp_log(s, LOG_DEBUG, "starting TLS");
  gnutls_init(&s->gnutls_session, GNUTLS_CLIENT);
  gnutls_session_set_ptr(s->gnutls_session, s);
  gnutls_alpn_set_protocols(s->gnutls_session, &xmpp_client_protocol, 1, 0);
  gnutls_server_name_set(s->gnutls_session, GNUTLS_NAME_DNS,
                         s->initial_jid.domain,
                         strlen(s->initial_jid.domain));
  gnutls_set_default_priority(s->gnutls_session);
  gnutls_credentials_set(s->gnutls_session, GNUTLS_CRD_CERTIFICATE,
                         s->gnutls_cred);
  gnutls_transport_set_int(s->gnutls_session, s->server_socket);
  gnutls_handshake_set_timeout(s->gnutls_session,
                               GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
  if (s->tls_session_data != NULL) {
    int ret = gnutls_session_set_data(s->gnutls_session,
                                      s->tls_session_data,
                                      s->tls_session_data_size);
    if (ret != GNUTLS_E_SUCCESS) {
      rexmpp_log(s, LOG_WARNING, "Failed to set TLS session data: %s",
                 gnutls_strerror(ret));
      free(s->tls_session_data);
      s->tls_session_data = NULL;
      s->tls_session_data_size = 0;
    }
  }
  s->tls_state = REXMPP_TLS_HANDSHAKE;
  return rexmpp_tls_handshake(s);
}

rexmpp_err_t rexmpp_connected_to_server (rexmpp_t *s) {
  s->tcp_state = REXMPP_TCP_CONNECTED;
  rexmpp_log(s, LOG_INFO,
             "Connected to the server, the used address record was %s",
             s->server_socket_dns_secure ? "secure" : "not secure");
  s->reconnect_number = 0;
  xmlCtxtResetPush(s->xml_parser, "", 0, "", "utf-8");
  if (s->tls_state == REXMPP_TLS_AWAITING_DIRECT) {
    return rexmpp_tls_start(s);
  } else {
    return rexmpp_stream_open(s);
  }
}

rexmpp_err_t rexmpp_process_socks_err (rexmpp_t *s, enum socks_err err) {
  if (err == REXMPP_SOCKS_CONNECTED) {
    return rexmpp_connected_to_server(s);
  } else if (err != REXMPP_SOCKS_E_AGAIN) {
    rexmpp_log(s, LOG_ERR, "SOCKS5 connection failed.");
    s->tcp_state = REXMPP_TCP_CONNECTION_FAILURE;
    close(s->server_socket);
    s->server_socket = -1;
    return rexmpp_try_next_host(s);
  }
  return REXMPP_E_AGAIN;
}

rexmpp_err_t
rexmpp_process_conn_err (rexmpp_t *s,
                         enum rexmpp_tcp_conn_error err)
{
  s->tcp_state = REXMPP_TCP_CONNECTING;
  if (err == REXMPP_CONN_DONE) {
    s->server_socket_dns_secure = s->server_connection.dns_secure;
    s->server_socket = rexmpp_tcp_conn_finish(&s->server_connection);
    if (s->socks_host == NULL) {
      return rexmpp_connected_to_server(s);
    } else {
      s->tcp_state = REXMPP_TCP_SOCKS;
      return
        rexmpp_process_socks_err(s, rexmpp_socks_init(&s->server_socks_conn,
                                                      s->server_socket,
                                                      s->server_host,
                                                      s->server_port));
    }
  } else if (err != REXMPP_CONN_IN_PROGRESS) {
    if (err == REXMPP_CONN_ERROR) {
      s->tcp_state = REXMPP_TCP_NONE;
    } else {
      s->tcp_state = REXMPP_TCP_CONNECTION_FAILURE;
    }
    rexmpp_tcp_conn_finish(&s->server_connection);
    return rexmpp_try_next_host(s);
  }
  return REXMPP_E_AGAIN;
}

void rexmpp_srv_cb (void *s_ptr,
                    int err,
                    struct ub_result *result)
{
  rexmpp_t *s = s_ptr;
  if (err == 0) {
    if (result->bogus) {
      rexmpp_log(s, LOG_WARNING,
                 "Received a bogus SRV resolution result for %s",
                 result->qname);
    } else if (result->havedata) {
      rexmpp_log(s,
                 result->secure ? LOG_DEBUG : LOG_WARNING,
                 "Resolved %s SRV record (%s)",
                 result->qname, result->secure ? "secure" : "not secure");
      if (strncmp("_xmpp-", result->qname, 6) == 0) {
        s->server_srv = result;
      } else {
        s->server_srv_tls = result;
      }
    } else {
      rexmpp_log(s, LOG_DEBUG, "No data in the %s SRV result", result->qname);
    }
  } else {
    rexmpp_log(s, LOG_WARNING, "Failed to query %s SRV records: %s",
               result->qname, ub_strerror(err));
  }

  if (s->resolver_state == REXMPP_RESOLVER_SRV) {
    s->resolver_state = REXMPP_RESOLVER_SRV_2;
  } else if (s->resolver_state == REXMPP_RESOLVER_SRV_2) {
    s->resolver_state = REXMPP_RESOLVER_READY;
  }
  if (s->resolver_state != REXMPP_RESOLVER_READY) {
    return;
  }

  /* todo: sort the records */

  if (s->server_srv == NULL && s->server_srv_tls == NULL) {
    /* Failed to resolve anything: a fallback. */
    s->server_host = s->initial_jid.domain;
    s->server_port = 5222;
    rexmpp_start_connecting(s);
  } else {
    rexmpp_try_next_host(s);
  }
}

/* Should be called after reconnect, and after rexmpp_sm_handle_ack in
   case of resumption. */
rexmpp_err_t rexmpp_resend_stanzas (rexmpp_t *s) {
  uint32_t i, count;
  rexmpp_err_t ret = REXMPP_SUCCESS;
  xmlNodePtr sq;
  count = s->stanzas_out_count - s->stanzas_out_acknowledged;
  for (i = 0; i < count && s->stanza_queue != NULL; i++) {
    sq = xmlNextElementSibling(s->stanza_queue);
    ret = rexmpp_send(s, s->stanza_queue);
    if (ret > REXMPP_E_AGAIN) {
      return ret;
    }
    s->stanza_queue = sq;
  }
  if (i != count) {
    rexmpp_log(s, LOG_ERR,
               "not enough stanzas in the queue: needed %u, had %u",
               count, i);
  }
  /* Don't count these stanzas twice. */
  s->stanzas_out_count -= i;
  return ret;
}

void rexmpp_sm_handle_ack (rexmpp_t *s, xmlNodePtr elem) {
  char *h = xmlGetProp(elem, "h");
  if (h != NULL) {
    uint32_t prev_ack = s->stanzas_out_acknowledged;
    s->stanzas_out_acknowledged = strtoul(h, NULL, 10);
    xmlFree(h);
    rexmpp_log(s, LOG_DEBUG,
               "server acknowledged %u out of %u sent stanzas",
               s->stanzas_out_acknowledged,
               s->stanzas_out_count);
    if (s->stanzas_out_count >= s->stanzas_out_acknowledged) {
      if (prev_ack <= s->stanzas_out_acknowledged) {
        uint32_t i;
        for (i = prev_ack; i < s->stanzas_out_acknowledged; i++) {
          xmlNodePtr sq = xmlNextElementSibling(s->stanza_queue);
          xmlFreeNode(s->stanza_queue);
          s->stanza_queue = sq;
        }
      } else {
        rexmpp_log(s, LOG_ERR,
                   "the server acknowledged %u stanzas previously, and %u now",
                   prev_ack, s->stanzas_out_acknowledged);
      }
    } else {
      rexmpp_log(s, LOG_ERR,
                 "the server acknowledged more stanzas than we have sent");
    }
  } else {
    rexmpp_log(s, LOG_ERR, "no 'h' attribute in <a>");
  }
}

void rexmpp_carbons_enabled (rexmpp_t *s,
                             xmlNodePtr req,
                             xmlNodePtr response,
                             int success)
{
  (void)req; /* The request is always the same. */
  (void)response; /* Only checking whether it's a success. */
  if (success) {
    rexmpp_log(s, LOG_INFO, "carbons enabled");
    s->carbons_state = REXMPP_CARBONS_ACTIVE;
  } else {
    rexmpp_log(s, LOG_WARNING, "failed to enable carbons");
    s->carbons_state = REXMPP_CARBONS_INACTIVE;
  }
}

void rexmpp_pong (rexmpp_t *s,
                  xmlNodePtr req,
                  xmlNodePtr response,
                  int success)
{
  (void)req;
  (void)response;
  (void)success;
  s->ping_requested = 0;
}

void rexmpp_iq_discovery_info (rexmpp_t *s,
                               xmlNodePtr req,
                               xmlNodePtr response,
                               int success)
{
  (void)req;
  if (! success) {
    rexmpp_log(s, LOG_ERR, "Failed to discover features");
    return;
  }
  xmlNodePtr query = xmlFirstElementChild(response);
  if (rexmpp_xml_match(query, "http://jabber.org/protocol/disco#info",
                       "query")) {
    xmlNodePtr child;
    for (child = xmlFirstElementChild(query);
         child != NULL;
         child = xmlNextElementSibling(child))
      {
        if (rexmpp_xml_match(child, "http://jabber.org/protocol/disco#info",
                             "feature")) {
          char *var = xmlGetProp(child, "var");
          if (s->enable_carbons &&
              strcmp(var, "urn:xmpp:carbons:2") == 0) {
            xmlNodePtr carbons_enable = xmlNewNode(NULL, "enable");
            xmlNewNs(carbons_enable, "urn:xmpp:carbons:2", NULL);
            s->carbons_state = REXMPP_CARBONS_NEGOTIATION;
            rexmpp_iq_new(s, "set", NULL, carbons_enable,
                          rexmpp_carbons_enabled);
          }
          free(var);
        }
      }
  }
}

void rexmpp_stream_is_ready(rexmpp_t *s) {
  s->stream_state = REXMPP_STREAM_READY;
  rexmpp_resend_stanzas(s);

  if (s->enable_service_discovery) {
    xmlNodePtr disco_query = xmlNewNode(NULL, "query");
    xmlNewNs(disco_query, "http://jabber.org/protocol/disco#info", NULL);
    rexmpp_iq_new(s, "get", s->initial_jid.domain,
                  disco_query, rexmpp_iq_discovery_info);
  }
  if (s->manage_roster) {
    if (s->roster_cache_file != NULL) {
      rexmpp_roster_cache_read(s);
    }
    xmlNodePtr roster_query = xmlNewNode(NULL, "query");
    xmlNewNs(roster_query, "jabber:iq:roster", NULL);
    if (s->roster_ver != NULL) {
      xmlNewProp(roster_query, "ver", s->roster_ver);
    } else {
      xmlNewProp(roster_query, "ver", "");
    }
    rexmpp_iq_new(s, "get", NULL,
                  roster_query, rexmpp_iq_roster_get);
  }
  xmlNodePtr presence = xmlNewNode(NULL, "presence");
  char *caps_hash = rexmpp_capabilities_hash(s, rexmpp_disco_info(s));
  if (caps_hash != NULL) {
    xmlNodePtr c = xmlNewNode(NULL, "c");
    xmlNewNs(c, "http://jabber.org/protocol/caps", NULL);
    xmlNewProp(c, "hash", "sha-1");
    xmlNewProp(c, "node", s->disco_node);
    xmlNewProp(c, "ver", caps_hash);
    xmlAddChild(presence, c);
    free(caps_hash);
  }
  rexmpp_send(s, presence);
}

/* Resource binding,
   https://tools.ietf.org/html/rfc6120#section-7 */
void rexmpp_bound (rexmpp_t *s, xmlNodePtr req, xmlNodePtr response, int success) {
  (void)req;
  if (! success) {
    /* todo: reconnect here? */
    rexmpp_log(s, LOG_ERR, "Resource binding failed.");
    return;
  }
  /* todo: handle errors */
  xmlNodePtr child = xmlFirstElementChild(response);
  if (rexmpp_xml_match(child, "urn:ietf:params:xml:ns:xmpp-bind", "bind")) {
    xmlNodePtr jid = xmlFirstElementChild(child);
    if (rexmpp_xml_match(jid, "urn:ietf:params:xml:ns:xmpp-bind", "jid")) {
      char *jid_str = xmlNodeGetContent(jid);
      rexmpp_log(s, LOG_INFO, "jid: %s", jid_str);
      rexmpp_jid_parse(jid_str, &(s->assigned_jid));
      free(jid_str);
    }
    if (s->stream_id == NULL &&
        (child = rexmpp_xml_find_child(s->stream_features, "urn:xmpp:sm:3",
                                       "sm"))) {
      /* Try to resume a stream. */
      s->sm_state = REXMPP_SM_NEGOTIATION;
      s->stream_state = REXMPP_STREAM_SM_FULL;
      xmlNodePtr sm_enable = xmlNewNode(NULL, "enable");
      xmlNewNs(sm_enable, "urn:xmpp:sm:3", NULL);
      xmlNewProp(sm_enable, "resume", "true");
      rexmpp_send(s, sm_enable);
      s->stanzas_out_count = 0;
      s->stanzas_out_acknowledged = 0;
      s->stanzas_in_count = 0;
    } else {
      s->sm_state = REXMPP_SM_INACTIVE;
      rexmpp_stream_is_ready(s);
    }
  }
}

rexmpp_err_t rexmpp_stream_bind (rexmpp_t *s) {
  /* Issue a bind request. */
  s->stream_state = REXMPP_STREAM_BIND;
  xmlNodePtr bind_cmd = xmlNewNode(NULL, "bind");
  xmlNewNs(bind_cmd, "urn:ietf:params:xml:ns:xmpp-bind", NULL);
  return rexmpp_iq_new(s, "set", NULL, bind_cmd, rexmpp_bound);
}

rexmpp_err_t rexmpp_process_element (rexmpp_t *s, xmlNodePtr elem) {
  rexmpp_console_on_recv(s, elem);

  /* IQs. These are the ones that should be processed by the library;
     if a user-facing application wants to handle them on its own, it
     should cancel further processing by the library (so we can send
     errors for unhandled IQs here). */
  if (rexmpp_xml_match(elem, "jabber:client", "iq")) {
    char *type = xmlGetProp(elem, "type");
    /* IQ responses. */
    if (strcmp(type, "result") == 0 || strcmp(type, "error") == 0) {
      char *id = xmlGetProp(elem, "id");
      rexmpp_iq_t *req = s->active_iq;
      int found = 0;
      while (req != NULL && found == 0) {
        char *req_id = xmlGetProp(req->request, "id");
        char *req_to = xmlGetProp(req->request, "to");
        char *rep_from = xmlGetProp(elem, "from");
        int id_matches = (strcmp(id, req_id) == 0);
        int jid_matches = 0;
        if (req_to == NULL && rep_from == NULL) {
          jid_matches = 1;
        } else if (req_to != NULL && rep_from != NULL) {
          jid_matches = (strcmp(req_to, rep_from) == 0);
        }
        if (id_matches && jid_matches) {
          found = 1;
          if (req->cb != NULL) {
            char *iq_type = xmlGetProp(elem, "type");
            int success = 0;
            if (strcmp(type, "result") == 0) {
              success = 1;
            }
            free(iq_type);
            req->cb(s, req->request, elem, success);
          }
          /* Remove the callback from the list, but keep in mind that
             it could have added more entries. */
          if (s->active_iq == req) {
            s->active_iq = req->next;
          } else {
            rexmpp_iq_t *prev_req = s->active_iq;
            for (prev_req = s->active_iq;
                 prev_req != NULL;
                 prev_req = prev_req->next)
              {
                if (prev_req->next == req) {
                  prev_req->next = req->next;
                  break;
                }
              }
          }
          xmlFreeNode(req->request);
          free(req);
        }
        if (req_to != NULL) {
          free(req_to);
        }
        if (rep_from != NULL) {
          free(rep_from);
        }
        free(req_id);
        req = req->next;
      }
      free(id);
    }
    /* IQ "set" requests. */
    if (strcmp(type, "set") == 0) {
      xmlNodePtr query = xmlFirstElementChild(elem);
      int from_server = 0;
      char *from = xmlGetProp(elem, "from");
      if (from == NULL) {
        from_server = 1;
      } else {
        if (strcmp(from, s->initial_jid.domain) == 0) {
          from_server = 1;
        }
        free(from);
      }
      if (from_server &&
          s->manage_roster &&
          rexmpp_xml_match(query, "jabber:iq:roster", "query")) {
        /* Roster push. */
        if (s->roster_ver != NULL) {
          free(s->roster_ver);
        }
        s->roster_ver = xmlGetProp(query, "ver");
        rexmpp_modify_roster(s, xmlFirstElementChild(query));
        /* todo: check for errors */
        rexmpp_iq_reply(s, elem, "result", NULL);
        if (s->roster_cache_file != NULL) {
          rexmpp_roster_cache_write(s);
        }
      } else {
        /* An unknown request. */
        rexmpp_iq_reply(s, elem, "error",
                        rexmpp_xml_error("cancel", "service-unavailable"));
      }
    }
    /* IQ "get" requests. */
    if (strcmp(type, "get") == 0) {
      xmlNodePtr query = xmlFirstElementChild(elem);
      if (rexmpp_xml_match(query, "http://jabber.org/protocol/disco#info", "query")) {
        char *node = xmlGetProp(query, "node");
        char *caps_hash = rexmpp_capabilities_hash(s, rexmpp_disco_info(s));
        if (node == NULL ||
            (caps_hash != NULL &&
             s->disco_node != NULL &&
             strlen(node) == strlen(s->disco_node) + 1 + strlen(caps_hash) &&
             strncmp(node, s->disco_node, strlen(s->disco_node)) == 0 &&
             node[strlen(s->disco_node)] == '#' &&
             strcmp(node + strlen(s->disco_node) + 1, caps_hash) == 0)) {
          xmlNodePtr result = xmlNewNode(NULL, "query");
          xmlNewNs(result, "http://jabber.org/protocol/disco#info", NULL);
          if (node != NULL) {
            xmlNewProp(result, "node", node);
          }
          xmlAddChild(result, xmlCopyNodeList(rexmpp_disco_info(s)));
          rexmpp_iq_reply(s, elem, "result", result);
        } else {
          rexmpp_log(s, LOG_WARNING,
                     "Service discovery request for an unknown node: %s", node);
          rexmpp_iq_reply(s, elem, "error",
                          rexmpp_xml_error("cancel", "item-not-found"));
        }
        if (caps_hash != NULL) {
          free(caps_hash);
        }
        if (node != NULL) {
          free(node);
        }
      } else if (rexmpp_xml_match(query, "urn:xmpp:ping", "ping")) {
        rexmpp_iq_reply(s, elem, "result", NULL);
      } else {
        /* An unknown request. */
        rexmpp_iq_reply(s, elem, "error",
                        rexmpp_xml_error("cancel", "service-unavailable"));
      }
    }
    free(type);
  }

  /* Incoming presence information. */
  if (rexmpp_xml_match(elem, "jabber:client", "presence") &&
      s->manage_roster &&
      s->track_roster_presence) {
    char *from = xmlGetProp(elem, "from");
    if (from != NULL) {
      struct rexmpp_jid from_jid;
      rexmpp_jid_parse(from, &from_jid);
      xmlFree(from);
      if (rexmpp_roster_find_item(s, from_jid.bare, NULL) != NULL) {
        /* The bare JID is in the roster. */
        char *type = xmlGetProp(elem, "type");
        xmlNodePtr cur, prev;
        if (type == NULL || strcmp(type, "unavailable") == 0) {
          /* Either a new "available" presence or an "unavailable"
             one: remove the previously stored presence for this
             JID. */
          for (prev = NULL, cur = s->roster_presence;
               cur != NULL;
               prev = cur, cur = xmlNextElementSibling(cur)) {
            char *cur_from = xmlGetProp(cur, "from");
            if (strcmp(cur_from, from_jid.full) == 0) {
              if (prev == NULL) {
                s->roster_presence = cur->next;
              } else {
                prev->next = cur->next;
              }
              xmlFreeNode(cur);
              cur = NULL;
            }
            free(cur_from);
          }
        }
        if (type == NULL) {
          /* An "available" presence: add it. */
          xmlNodePtr presence = xmlCopyNode(elem, 1);
          presence->next = s->roster_presence;
          s->roster_presence = presence;
        } else {
          free(type);
        }
      }
    }
  }

  /* Incoming messages. */
  if (rexmpp_xml_match(elem, "jabber:client", "message")) {
    char *from = xmlGetProp(elem, "from");
    if (from != NULL) {
      struct rexmpp_jid from_jid;
      rexmpp_jid_parse(from, &from_jid);
      xmlFree(from);
      if (rexmpp_roster_find_item(s, from_jid.bare, NULL) != NULL ||
          strcmp(from_jid.bare, s->assigned_jid.bare) == 0) {
        xmlNodePtr event =
          rexmpp_xml_find_child(elem,
                                "http://jabber.org/protocol/pubsub#event",
                                "event");
        if (event != NULL && s->manage_roster && s->track_roster_events) {
          xmlNodePtr items =
            rexmpp_xml_find_child(event,
                                  "http://jabber.org/protocol/pubsub#event",
                                  "items");
          if (items != NULL) {
            char *node = xmlGetProp(items, "node");
            if (node != NULL) {
              /* Remove the previously stored items for the same sender
                 and node, if any. */
              xmlNodePtr prev, cur;
              cur = rexmpp_find_event(s, from_jid.bare, node, &prev);
              if (cur) {
                if (prev == NULL) {
                  s->roster_events = cur->next;
                } else {
                  prev->next = cur->next;
                }
              }

              /* Add the new message. */
              xmlNodePtr message = xmlCopyNode(elem, 1);
              message->next = s->roster_events;
              s->roster_events = message;

              /* Process the node at once. */
              if (s->retrieve_openpgp_keys &&
                  strcmp(node, "urn:xmpp:openpgp:0:public-keys") == 0) {
                rexmpp_openpgp_check_keys(s, from_jid.bare, items);
              }
              if (s->autojoin_bookmarked_mucs &&
                  strcmp(node, "urn:xmpp:bookmarks:1") == 0 &&
                  strcmp(from_jid.bare, s->assigned_jid.bare) == 0) {
                xmlNodePtr item;
                for (item = xmlFirstElementChild(items);
                     item != NULL;
                     item = xmlNextElementSibling(item)) {
                  xmlNodePtr conference =
                    rexmpp_xml_find_child(item,
                                          "urn:xmpp:bookmarks:1",
                                          "conference");
                  if (conference == NULL) {
                    continue;
                  }
                  char *item_id = xmlGetProp(item, "id");
                  if (item_id == NULL) {
                    continue;
                  }
                  char *autojoin = xmlGetProp(conference, "autojoin");
                  if (autojoin == NULL) {
                    free(item_id);
                    continue;
                  }
                  if (strcmp(autojoin, "true") == 0 ||
                      strcmp(autojoin, "1") == 0) {
                    xmlNodePtr presence =
                      rexmpp_xml_add_id(s, xmlNewNode(NULL, "presence"));
                    xmlNewProp(presence, "from", s->assigned_jid.full);
                    xmlNodePtr nick =
                      rexmpp_xml_find_child(conference,
                                            "urn:xmpp:bookmarks:1",
                                            "nick");
                    char *nick_str;
                    if (nick != NULL) {
                      nick_str = xmlNodeGetContent(nick);
                    } else {
                      nick_str = strdup(s->initial_jid.local);
                    }
                    char *jid = malloc(strlen(item_id) + strlen(nick_str) + 2);
                    sprintf(jid, "%s/%s", item_id, nick_str);
                    free(nick_str);
                    xmlNewProp(presence, "to", jid);
                    free(jid);
                    xmlNodePtr x = xmlNewNode(NULL, "x");
                    xmlNewNs(x, "http://jabber.org/protocol/muc", NULL);
                    xmlAddChild(presence, x);
                    rexmpp_send(s, presence);
                  }
                  free(item_id);
                  free(autojoin);
                }
              }
              free(node);
            }
          }
        }
      }
    }
  }

  /* Stream negotiation,
     https://tools.ietf.org/html/rfc6120#section-4.3 */
  if (s->stream_state == REXMPP_STREAM_NEGOTIATION &&
      rexmpp_xml_match(elem, "http://etherx.jabber.org/streams", "features")) {

    /* Remember features. */
    if (s->stream_features != NULL) {
      xmlFreeNode(s->stream_features);
    }
    s->stream_features = xmlCopyNode(elem, 1);

    /* Nothing to negotiate. */
    if (xmlFirstElementChild(elem) == NULL) {
      rexmpp_stream_is_ready(s);
      return REXMPP_SUCCESS;
    }

    /* TODO: check for required features properly here. Currently
       assuming that STARTTLS, SASL, and BIND (with an exception for
       SM) are always required if they are present. */
    xmlNodePtr child =
      rexmpp_xml_find_child(elem, "urn:ietf:params:xml:ns:xmpp-tls",
                            "starttls");
    if (child != NULL) {
      s->stream_state = REXMPP_STREAM_STARTTLS;
      xmlNodePtr starttls_cmd = xmlNewNode(NULL, "starttls");
      xmlNewNs(starttls_cmd, "urn:ietf:params:xml:ns:xmpp-tls", NULL);
      rexmpp_send(s, starttls_cmd);
      return REXMPP_SUCCESS;
    }

    child = rexmpp_xml_find_child(elem, "urn:ietf:params:xml:ns:xmpp-sasl",
                                  "mechanisms");
    if (child != NULL) {
      s->stream_state = REXMPP_STREAM_SASL;
      s->sasl_state = REXMPP_SASL_NEGOTIATION;
      char mech_list[2048];   /* todo: perhaps grow it dynamically */
      mech_list[0] = '\0';
      xmlNodePtr mechanism;
      for (mechanism = xmlFirstElementChild(child);
           mechanism != NULL;
           mechanism = xmlNextElementSibling(mechanism)) {
        if (rexmpp_xml_match(mechanism, "urn:ietf:params:xml:ns:xmpp-sasl",
                             "mechanism")) {
          char *mech_str = xmlNodeGetContent(mechanism);
          snprintf(mech_list + strlen(mech_list),
                   2048 - strlen(mech_list),
                   "%s ",
                   mech_str);
          free(mech_str);
        }
      }
      const char *mech =
        gsasl_client_suggest_mechanism(s->sasl_ctx, mech_list);
      rexmpp_log(s, LOG_INFO, "Selected SASL mechanism: %s", mech);
      int sasl_err;
      char *sasl_buf;
      sasl_err = gsasl_client_start(s->sasl_ctx, mech, &(s->sasl_session));
      if (sasl_err != GSASL_OK) {
        rexmpp_log(s, LOG_CRIT, "Failed to initialise SASL session: %s",
                   gsasl_strerror(sasl_err));
        s->sasl_state = REXMPP_SASL_ERROR;
        return REXMPP_E_SASL;
      }
      sasl_err = gsasl_step64 (s->sasl_session, "", (char**)&sasl_buf);
      if (sasl_err != GSASL_OK) {
        if (sasl_err == GSASL_NEEDS_MORE) {
          rexmpp_log(s, LOG_DEBUG, "SASL needs more data");
        } else {
          rexmpp_log(s, LOG_ERR, "SASL error: %s",
                     gsasl_strerror(sasl_err));
          s->sasl_state = REXMPP_SASL_ERROR;
          return REXMPP_E_SASL;
        }
      }
      xmlNodePtr auth_cmd = xmlNewNode(NULL, "auth");
      xmlNewProp(auth_cmd, "mechanism", mech);
      xmlNewNs(auth_cmd, "urn:ietf:params:xml:ns:xmpp-sasl", NULL);
      xmlNodeAddContent(auth_cmd, sasl_buf);
      free(sasl_buf);
      rexmpp_send(s, auth_cmd);
      return REXMPP_SUCCESS;
    }

    child = rexmpp_xml_find_child(elem, "urn:xmpp:sm:3", "sm");
    if (s->stream_id != NULL && child != NULL) {
      s->stream_state = REXMPP_STREAM_SM_RESUME;
      char buf[11];
      snprintf(buf, 11, "%u", s->stanzas_in_count);
      xmlNodePtr sm_resume = xmlNewNode(NULL, "resume");
      xmlNewNs(sm_resume, "urn:xmpp:sm:3", NULL);
      xmlNewProp(sm_resume, "previd", s->stream_id);
      xmlNewProp(sm_resume, "h", buf);
      rexmpp_send(s, sm_resume);
      return REXMPP_SUCCESS;
    }

    child =
      rexmpp_xml_find_child(elem, "urn:ietf:params:xml:ns:xmpp-bind", "bind");
    if (child != NULL) {
      return rexmpp_stream_bind(s);
    }
  }

  /* Stream errors, https://tools.ietf.org/html/rfc6120#section-4.9 */
  if (rexmpp_xml_match(elem, "http://etherx.jabber.org/streams",
                       "error")) {
    if (rexmpp_xml_find_child(elem, "urn:ietf:params:xml:ns:xmpp-streams",
                              "reset") != NULL ||
        rexmpp_xml_find_child(elem, "urn:ietf:params:xml:ns:xmpp-streams",
                              "system-shutdown") != NULL) {
      rexmpp_log(s, LOG_WARNING, "Server reset or shutdown.");
      s->stream_state = REXMPP_STREAM_ERROR_RECONNECT;
      return REXMPP_E_AGAIN;
    } else {
      rexmpp_log(s, LOG_ERR, "Stream error");
      s->stream_state = REXMPP_STREAM_ERROR;
      return REXMPP_E_STREAM;
    }
  }

  /* STARTTLS negotiation,
     https://tools.ietf.org/html/rfc6120#section-5 */
  if (s->stream_state == REXMPP_STREAM_STARTTLS) {
    if (rexmpp_xml_match(elem, "urn:ietf:params:xml:ns:xmpp-tls",
                         "proceed")) {
      return rexmpp_tls_start(s);
    } else if (rexmpp_xml_match(elem, "urn:ietf:params:xml:ns:xmpp-tls",
                                "failure")) {
      rexmpp_log(s, LOG_ERR, "STARTTLS failure");
      return REXMPP_E_TLS;
    }
  }

  /* SASL negotiation,
     https://tools.ietf.org/html/rfc6120#section-6 */
  if (s->stream_state == REXMPP_STREAM_SASL) {
    char *sasl_buf;
    int sasl_err;
    if (rexmpp_xml_match(elem, "urn:ietf:params:xml:ns:xmpp-sasl",
                         "challenge")) {
      char *challenge = xmlNodeGetContent(elem);
      sasl_err = gsasl_step64 (s->sasl_session, challenge,
                               (char**)&sasl_buf);
      free(challenge);
      if (sasl_err != GSASL_OK) {
        if (sasl_err == GSASL_NEEDS_MORE) {
          rexmpp_log(s, LOG_DEBUG, "SASL needs more data");
        } else {
          rexmpp_log(s, LOG_ERR, "SASL error: %s",
                     gsasl_strerror(sasl_err));
          s->sasl_state = REXMPP_SASL_ERROR;
          return REXMPP_E_SASL;
        }
      }
      xmlNodePtr response = xmlNewNode(NULL, "response");
      xmlNewNs(response, "urn:ietf:params:xml:ns:xmpp-sasl", NULL);
      xmlNodeAddContent(response, sasl_buf);
      free(sasl_buf);
      return rexmpp_send(s, response);
    } else if (rexmpp_xml_match(elem, "urn:ietf:params:xml:ns:xmpp-sasl",
                                "success")) {
      char *success = xmlNodeGetContent(elem);
      sasl_err = gsasl_step64 (s->sasl_session, success,
                               (char**)&sasl_buf);
      free(success);
      free(sasl_buf);
      if (sasl_err == GSASL_OK) {
        rexmpp_log(s, LOG_DEBUG, "SASL success");
      } else {
        rexmpp_log(s, LOG_ERR, "SASL error: %s",
                   gsasl_strerror(sasl_err));
        s->sasl_state = REXMPP_SASL_ERROR;
        return REXMPP_E_SASL;
      }
      s->sasl_state = REXMPP_SASL_ACTIVE;
      xmlCtxtResetPush(s->xml_parser, "", 0, "", "utf-8");
      return rexmpp_stream_open(s);
    } else if (rexmpp_xml_match(elem, "urn:ietf:params:xml:ns:xmpp-sasl",
                                "failure")) {
      /* todo: would be nice to retry here, but just giving up for now */
      rexmpp_log(s, LOG_ERR, "SASL failure");
      return rexmpp_stop(s);
    }
  }

  /* Stream management, https://xmpp.org/extensions/xep-0198.html */
  if (s->stream_state == REXMPP_STREAM_SM_FULL) {
    if (rexmpp_xml_match(elem, "urn:xmpp:sm:3", "enabled")) {
      s->sm_state = REXMPP_SM_ACTIVE;
      char *resume = xmlGetProp(elem, "resume");
      if (resume != NULL) {
        if (s->stream_id != NULL) {
          free(s->stream_id);
        }
        s->stream_id = xmlGetProp(elem, "id");
        xmlFree(resume);
      }
      rexmpp_stream_is_ready(s);
    } else if (rexmpp_xml_match(elem, "urn:xmpp:sm:3", "failed")) {
      s->stream_state = REXMPP_STREAM_SM_ACKS;
      s->sm_state = REXMPP_SM_NEGOTIATION;
      xmlNodePtr sm_enable = xmlNewNode(NULL, "enable");
      xmlNewNs(sm_enable, "urn:xmpp:sm:3", NULL);
      rexmpp_send(s, sm_enable);
    }
  } else if (s->stream_state == REXMPP_STREAM_SM_ACKS) {
    if (rexmpp_xml_match(elem, "urn:xmpp:sm:3", "enabled")) {
      s->sm_state = REXMPP_SM_ACTIVE;
      if (s->stream_id != NULL) {
        free(s->stream_id);
        s->stream_id = NULL;
      }
    } else if (rexmpp_xml_match(elem, "urn:xmpp:sm:3", "failed")) {
      s->sm_state = REXMPP_SM_INACTIVE;
      xmlNodePtr sm_enable = xmlNewNode(NULL, "enable");
      xmlNewNs(sm_enable, "urn:xmpp:sm:3", NULL);
      rexmpp_send(s, sm_enable);
    }
    rexmpp_stream_is_ready(s);
  } else if (s->stream_state == REXMPP_STREAM_SM_RESUME) {
    if (rexmpp_xml_match(elem, "urn:xmpp:sm:3", "resumed")) {
      s->sm_state = REXMPP_SM_ACTIVE;
      s->stream_state = REXMPP_STREAM_READY;
      rexmpp_sm_handle_ack(s, elem);
      rexmpp_resend_stanzas(s);
    } else if (rexmpp_xml_match(elem, "urn:xmpp:sm:3", "failed")) {
      /* Back to binding, but cleanup stream state first. */
      free(s->stream_id);
      s->stream_id = NULL;
      while (s->active_iq != NULL) {
        /* todo: check that those are not queued for resending? */
        rexmpp_iq_t *next = s->active_iq->next;
        xmlFreeNode(s->active_iq->request);
        free(s->active_iq);
        s->active_iq = next;
      }
      xmlNodePtr child =
        rexmpp_xml_find_child(s->stream_features,
                              "urn:ietf:params:xml:ns:xmpp-bind",
                              "bind");
      if (child != NULL) {
        return rexmpp_stream_bind(s);
      }
    }
  }

  if (s->sm_state == REXMPP_SM_ACTIVE && rexmpp_xml_is_stanza(elem)) {
    s->stanzas_in_count++;
  }
  if (rexmpp_xml_match(elem, "urn:xmpp:sm:3", "r")) {
    return rexmpp_sm_ack(s);
  } else if (rexmpp_xml_match(elem, "urn:xmpp:sm:3", "a")) {
    rexmpp_sm_handle_ack(s, elem);
  }
  return REXMPP_SUCCESS;
}


void rexmpp_sax_characters (rexmpp_t *s, const char *ch, int len)
{
  if (s->current_element != NULL) {
    xmlNodeAddContentLen(s->current_element, ch, len);
  }
}

void rexmpp_sax_start_elem_ns (rexmpp_t *s,
                               const char *localname,
                               const char *prefix,
                               const char *URI,
                               int nb_namespaces,
                               const char **namespaces,
                               int nb_attributes,
                               int nb_defaulted,
                               const char **attributes)
{
  /* Not checking namespaces beyond URI. */
  (void)nb_namespaces;
  (void)namespaces;
  (void)nb_defaulted;

  int i;
  if (s->stream_state == REXMPP_STREAM_OPENING &&
      strcmp(localname, "stream") == 0 &&
      strcmp(URI, "http://etherx.jabber.org/streams") == 0) {
    rexmpp_log(s, LOG_DEBUG, "stream start");
    s->stream_state = REXMPP_STREAM_NEGOTIATION;
    return;
  }

  if (s->stream_state != REXMPP_STREAM_OPENING) {
    if (s->current_element == NULL) {
      s->current_element = xmlNewNode(NULL, localname);
      s->current_element_root = s->current_element;
    } else {
      xmlNodePtr node = xmlNewNode(NULL, localname);
      xmlAddChild(s->current_element, node);
      s->current_element = node;
    }
    xmlNsPtr ns = xmlNewNs(s->current_element, URI, prefix);
    s->current_element->ns = ns;
    for (i = 0; i < nb_attributes; i++) {
      size_t attr_len = attributes[i * 5 + 4] - attributes[i * 5 + 3];
      char *attr_val = malloc(attr_len + 1);
      attr_val[attr_len] = '\0';
      strncpy(attr_val, attributes[i * 5 + 3], attr_len);
      xmlNewProp(s->current_element, attributes[i * 5], attr_val);
      free(attr_val);
    }
  }
}

void rexmpp_sax_end_elem_ns (rexmpp_t *s,
                             const char *localname,
                             const char *prefix,
                             const char *URI)
{
  (void)prefix;                 /* Not interested in prefix here. */
  if ((s->stream_state == REXMPP_STREAM_CLOSING ||
       s->stream_state == REXMPP_STREAM_ERROR) &&
      strcmp(localname, "stream") == 0 &&
      strcmp(URI, "http://etherx.jabber.org/streams") == 0) {
    rexmpp_log(s, LOG_DEBUG, "stream end");
    if (s->sasl_state == REXMPP_SASL_ACTIVE) {
      gsasl_finish(s->sasl_session);
      s->sasl_session = NULL;
      s->sasl_state = REXMPP_SASL_INACTIVE;
    }
    s->stream_state = REXMPP_STREAM_CLOSED;
    if (s->tls_state == REXMPP_TLS_ACTIVE) {
      s->tls_state = REXMPP_TLS_CLOSING;
    } else {
      rexmpp_log(s, LOG_DEBUG, "closing the socket");
      close(s->server_socket);
      s->server_socket = -1;
      rexmpp_cleanup(s);
      s->tcp_state = REXMPP_TCP_CLOSED;
    }
    return;
  }

  if (s->current_element != s->current_element_root) {
    s->current_element = s->current_element->parent;
  } else {
    if (s->input_queue == NULL) {
      s->input_queue = s->current_element;
      s->input_queue_last = s->current_element;
    } else {
      s->input_queue_last->next = s->current_element;
      s->input_queue_last = s->current_element;
    }
    s->current_element = NULL;
    s->current_element_root = NULL;
  }
}

rexmpp_err_t rexmpp_close (rexmpp_t *s) {
  s->stream_state = REXMPP_STREAM_CLOSING;
  char *close_stream = "</stream:stream>";
  return rexmpp_send_raw(s, close_stream, strlen(close_stream));
}

rexmpp_err_t rexmpp_stop (rexmpp_t *s) {
  if (s->stream_state == REXMPP_STREAM_READY) {
    xmlNodePtr presence = xmlNewNode(NULL, "presence");
    xmlNewProp(presence, "type", "unavailable");
    rexmpp_send(s, presence);
  }
  if (s->sm_state == REXMPP_SM_ACTIVE) {
    int ret = rexmpp_sm_ack(s);
    if (ret > REXMPP_E_AGAIN) {
      return ret;
    }
  }
  s->stream_state = REXMPP_STREAM_CLOSE_REQUESTED;
  if (s->send_buffer == NULL) {
    return rexmpp_close(s);
  } else {
    return REXMPP_E_AGAIN;
  }
}

rexmpp_err_t rexmpp_run (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds) {
  struct timeval now;
  if (gettimeofday(&now, NULL) != 0) {
    rexmpp_log(s, LOG_ERR, "Failed to get time: %s", strerror(errno));
    return REXMPP_E_OTHER;
  }

  /* Inactive: start or reconnect. */
  if ((s->resolver_state == REXMPP_RESOLVER_NONE ||
       s->resolver_state == REXMPP_RESOLVER_READY) &&
      (s->tcp_state == REXMPP_TCP_NONE ||
       ((s->tcp_state == REXMPP_TCP_ERROR ||
         s->tcp_state == REXMPP_TCP_CONNECTION_FAILURE) &&
        s->reconnect_number > 0 &&
        s->next_reconnect_time.tv_sec <= now.tv_sec))) {
    if (s->manual_host == NULL) {
      /* Start by querying SRV records. */
      rexmpp_log(s, LOG_DEBUG, "start (or reconnect)");
      size_t srv_query_buf_len = strlen(s->initial_jid.domain) +
        strlen("_xmpps-client._tcp..") +
        1;
      char *srv_query = malloc(srv_query_buf_len);
      if (srv_query == NULL) {
        return REXMPP_E_MALLOC;
      }
      snprintf(srv_query, srv_query_buf_len,
               "_xmpps-client._tcp.%s.", s->initial_jid.domain);
      int err;
      err = ub_resolve_async(s->resolver_ctx, srv_query, 33, 1,
                             s, rexmpp_srv_cb, NULL);
      if (err) {
        rexmpp_log(s, LOG_ERR, "Failed to query %s SRV record: %s",
                   srv_query, ub_strerror(err));
      }
      snprintf(srv_query, srv_query_buf_len,
               "_xmpp-client._tcp.%s.", s->initial_jid.domain);
      err = ub_resolve_async(s->resolver_ctx, srv_query, 33, 1,
                             s, rexmpp_srv_cb, NULL);
      if (err) {
        rexmpp_log(s, LOG_ERR, "Failed to query %s SRV record: %s",
                   srv_query, ub_strerror(err));
      }
      s->resolver_state = REXMPP_RESOLVER_SRV;
      free(srv_query);
    } else {
      /* A host is configured manually, connect there. */
      s->server_host = s->manual_host;
      s->server_port = s->manual_port;
      if (s->manual_direct_tls) {
        s->tls_state = REXMPP_TLS_AWAITING_DIRECT;
      } else {
        s->tls_state = REXMPP_TLS_INACTIVE;
      }
      rexmpp_err_t err = rexmpp_start_connecting(s);
      if (err > REXMPP_E_AGAIN) {
        return err;
      }
    }
  }

  /* Resolving SRV records. This continues in rexmpp_srv_tls_cb,
     rexmpp_srv_cb, and rexmpp_after_srv, possibly leading to
     connection initiation. */
  if (s->resolver_state != REXMPP_RESOLVER_NONE &&
      s->resolver_state != REXMPP_RESOLVER_READY) {
    if (ub_poll(s->resolver_ctx)) {
      int err = ub_process(s->resolver_ctx);
      if (err != 0) {
        rexmpp_log(s, LOG_ERR, "DNS query processing error: %s",
                   ub_strerror(err));
        return REXMPP_E_DNS;
      }
    }
  }

  /* Connecting. Continues in rexmpp_process_conn_err, possibly
     leading to stream opening. */
  if (s->tcp_state == REXMPP_TCP_CONNECTING) {
    rexmpp_err_t err =
      rexmpp_process_conn_err(s,
                              rexmpp_tcp_conn_proceed(&s->server_connection,
                                                      read_fds, write_fds));
    if (err > REXMPP_E_AGAIN) {
      return err;
    }
  }

  /* SOCKS5 connection. */
  if (s->tcp_state == REXMPP_TCP_SOCKS) {
    rexmpp_err_t err =
      rexmpp_process_socks_err(s, rexmpp_socks_proceed(&s->server_socks_conn));
    if (err > REXMPP_E_AGAIN) {
      return err;
    }
  }

  /* The things we do while connected. */

  /* Sending queued data. */
  if (s->tcp_state == REXMPP_TCP_CONNECTED &&
      FD_ISSET(s->server_socket, write_fds) &&
      (s->tls_state == REXMPP_TLS_ACTIVE ||
       s->tls_state == REXMPP_TLS_INACTIVE) &&
      (s->stream_state != REXMPP_STREAM_NONE &&
       s->stream_state != REXMPP_STREAM_CLOSED &&
       s->stream_state != REXMPP_STREAM_ERROR) &&
      s->sasl_state != REXMPP_SASL_ERROR &&
      s->send_buffer != NULL) {
    rexmpp_err_t err = rexmpp_send_continue(s);
    if (err > REXMPP_E_AGAIN) {
      return err;
    }
  }

  /* Pinging the server. */
  if (s->tcp_state == REXMPP_TCP_CONNECTED &&
      s->last_network_activity + s->ping_delay <= time(NULL)) {
    if (s->ping_requested == 0) {
      s->ping_requested = 1;
      xmlNodePtr ping_cmd = xmlNewNode(NULL, "ping");
      xmlNewNs(ping_cmd, "urn:xmpp:ping", NULL);
      rexmpp_iq_new(s, "get", s->initial_jid.domain,
                    ping_cmd, rexmpp_pong);
    } else {
      rexmpp_log(s, LOG_WARNING, "Ping timeout, reconnecting.");
      rexmpp_cleanup(s);
      rexmpp_schedule_reconnect(s);
    }
  }

  /* Receiving data. Leads to all kinds of things. */
  if (s->tcp_state == REXMPP_TCP_CONNECTED &&
      FD_ISSET(s->server_socket, read_fds) &&
      (s->tls_state == REXMPP_TLS_ACTIVE ||
       s->tls_state == REXMPP_TLS_INACTIVE) &&
      (s->stream_state != REXMPP_STREAM_NONE &&
       s->stream_state != REXMPP_STREAM_CLOSED &&
       s->stream_state != REXMPP_STREAM_ERROR) &&
      s->sasl_state != REXMPP_SASL_ERROR) {
    rexmpp_err_t err = rexmpp_recv(s);
    if (err > REXMPP_E_AGAIN) {
      return err;
    }
  }

  /* Performing a TLS handshake. A stream restart happens after
     this, if everything goes well. */
  if (s->tcp_state == REXMPP_TCP_CONNECTED &&
      s->tls_state == REXMPP_TLS_HANDSHAKE) {
    rexmpp_err_t err = rexmpp_tls_handshake(s);
    if (err > REXMPP_E_AGAIN) {
      return err;
    }
  }

  /* Closing the stream once everything is sent. */
  if (s->tcp_state == REXMPP_TCP_CONNECTED &&
      s->stream_state == REXMPP_STREAM_CLOSE_REQUESTED &&
      s->send_buffer == NULL) {
    rexmpp_err_t err = rexmpp_close(s);
    if (err > REXMPP_E_AGAIN) {
      return err;
    }
  }

  /* Closing TLS and TCP connections once stream is closed. If
     there's no TLS, the TCP connection is closed at once
     elsewhere. */
  if (s->tcp_state == REXMPP_TCP_CONNECTED &&
      s->stream_state == REXMPP_STREAM_CLOSED &&
      s->tls_state == REXMPP_TLS_CLOSING) {
    int ret = gnutls_bye(s->gnutls_session, GNUTLS_SHUT_RDWR);
    if (ret == GNUTLS_E_SUCCESS) {
      s->tls_state = REXMPP_TLS_INACTIVE;
      rexmpp_cleanup(s);
      s->tcp_state = REXMPP_TCP_CLOSED;
    } else {
      rexmpp_log(s, LOG_WARNING, "Failed to close TLS connection: %s",
                 gnutls_strerror(ret));
      return REXMPP_E_TLS;
    }
  }

  if (s->tcp_state == REXMPP_TCP_CLOSED &&
      s->stream_state != REXMPP_STREAM_ERROR_RECONNECT) {
    rexmpp_console_on_run(s, REXMPP_SUCCESS);
    return REXMPP_SUCCESS;
  } else {
    rexmpp_console_on_run(s, REXMPP_E_AGAIN);
    return REXMPP_E_AGAIN;
  }
}

int rexmpp_fds(rexmpp_t *s, fd_set *read_fds, fd_set *write_fds) {
  int conn_fd, max_fd = 0;

  if (s->resolver_state != REXMPP_RESOLVER_NONE &&
      s->resolver_state != REXMPP_RESOLVER_READY) {
    max_fd = ub_fd(s->resolver_ctx) + 1;
    if (max_fd != 0) {
      FD_SET(max_fd - 1, read_fds);
    }
  }

  if (s->tcp_state == REXMPP_TCP_CONNECTING) {
    conn_fd = rexmpp_tcp_conn_fds(&s->server_connection, read_fds, write_fds);
    if (conn_fd > max_fd) {
      max_fd = conn_fd;
    }
  }

  if (s->tcp_state == REXMPP_TCP_SOCKS) {
    if (s->server_socks_conn.io_state == REXMPP_SOCKS_WRITING) {
      FD_SET(s->server_socket, write_fds);
    } else {
      FD_SET(s->server_socket, read_fds);
    }
    if (s->server_socket + 1 > max_fd) {
      max_fd = s->server_socket + 1;
    }
  }

  if (s->tls_state == REXMPP_TLS_HANDSHAKE) {
    if (gnutls_record_get_direction(s->gnutls_session) == 0) {
      FD_SET(s->server_socket, read_fds);
    } else {
      FD_SET(s->server_socket, write_fds);
    }
    if (s->server_socket + 1 > max_fd) {
      max_fd = s->server_socket + 1;
    }
  }

  if (s->tcp_state == REXMPP_TCP_CONNECTED) {
    FD_SET(s->server_socket, read_fds);
    if (s->send_buffer != NULL) {
      FD_SET(s->server_socket, write_fds);
    }
    if (s->server_socket + 1 > max_fd) {
      max_fd = s->server_socket + 1;
    }
  }

  return max_fd;
}

struct timeval *rexmpp_timeout (rexmpp_t *s,
                                struct timeval *max_tv,
                                struct timeval *tv)
{
  struct timeval *ret = max_tv;

  if (s->resolver_state != REXMPP_RESOLVER_NONE &&
      s->resolver_state != REXMPP_RESOLVER_READY) {

  } else if (s->tcp_state == REXMPP_TCP_CONNECTING) {
    ret = rexmpp_tcp_conn_timeout(&s->server_connection, max_tv, tv);
  }
  struct timeval now;
  gettimeofday(&now, NULL);
  if (s->reconnect_number > 0 &&
      s->next_reconnect_time.tv_sec > now.tv_sec &&
      (ret == NULL ||
       s->next_reconnect_time.tv_sec - now.tv_sec < ret->tv_sec)) {
    tv->tv_sec = s->next_reconnect_time.tv_sec - now.tv_sec;
    tv->tv_usec = 0;
    ret = tv;
  }

  if (s->tcp_state == REXMPP_TCP_CONNECTED &&
      s->last_network_activity + s->ping_delay > now.tv_sec) {
    time_t next_ping = s->last_network_activity + s->ping_delay - now.tv_sec;
    if (ret == NULL || next_ping < ret->tv_sec) {
      tv->tv_sec = next_ping;
      tv->tv_usec = 0;
      ret = tv;
    }
  }

  return ret;
}
