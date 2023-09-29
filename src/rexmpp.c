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
#include <assert.h>

#include "config.h"

#ifdef HAVE_GCRYPT
#include <gcrypt.h>
#endif
#ifdef USE_UNBOUND
#include <unbound.h>
#endif
#ifdef HAVE_GPGME
#include <gpgme.h>
#endif
#ifdef HAVE_CURL
#include <curl/curl.h>
#endif

#include "rexmpp.h"
#include "rexmpp_xml.h"
#include "rexmpp_tcp.h"
#include "rexmpp_socks.h"
#include "rexmpp_roster.h"
#include "rexmpp_dns.h"
#include "rexmpp_jid.h"
#include "rexmpp_openpgp.h"
#include "rexmpp_console.h"
#include "rexmpp_http_upload.h"
#include "rexmpp_jingle.h"
#include "rexmpp_base64.h"
#include "rexmpp_sasl.h"
#include "rexmpp_random.h"
#include "rexmpp_digest.h"

struct rexmpp_iq_cacher {
  rexmpp_iq_callback_t cb;
  void *cb_data;
};

struct rexmpp_feature_search {
  const char *feature_var;
  int max_requests;
  int pending;
  rexmpp_iq_callback_t cb;
  void *cb_data;
  int fresh;
  int found;
};

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
                               const char *name,
                               const char *namespace,
                               rexmpp_xml_attr_t *attributes);

void rexmpp_sax_end_elem_ns(rexmpp_t *s);

void rexmpp_sax_characters (rexmpp_t *s, const char * ch, size_t len);

void rexmpp_log (rexmpp_t *s, int priority, const char *format, ...)
{
  va_list args;
  if (s->log_function != NULL) {
    va_start(args, format);
    s->log_function (s, priority, format, args);
    va_end(args);
  }
}

char *rexmpp_capabilities_string (rexmpp_t *s, rexmpp_xml_t *info) {
  /* Assuming the info is sorted already. Would be better to sort it
     here (todo). */
  rexmpp_xml_t *cur;
  int buf_len = 1024, str_len = 0;
  char *str = malloc(buf_len);
  for (cur = info; cur; cur = cur->next) {
    if (strcmp(cur->alt.elem.qname.name, "identity") == 0) {
      int cur_len = 5;          /* ///< for an empty identity */

      /* Collect the properties we'll need. */
      const char *category = rexmpp_xml_find_attr_val(cur, "category");
      const char *type = rexmpp_xml_find_attr_val(cur, "type");
      const char *lang = rexmpp_xml_find_attr_val(cur, "xml:lang");
      const char *name = rexmpp_xml_find_attr_val(cur, "name");

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
    } else if (strcmp(cur->alt.elem.qname.name, "feature") == 0) {
      const char *var = rexmpp_xml_find_attr_val(cur, "var");
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
    } else {
      rexmpp_log(s, LOG_ERR,
                 "Unsupported node type in disco info: %s", cur->alt.elem.qname.name);
    }
  }
  str[str_len] = '\0';
  return str;
}

char *rexmpp_capabilities_hash (rexmpp_t *s,
                                rexmpp_xml_t *info)
{
  char *out = NULL;
  size_t out_len = 0;
  char *str = rexmpp_capabilities_string(s, info);
  if (str != NULL) {
    size_t sha1_len = rexmpp_digest_len(REXMPP_DIGEST_SHA1);
    char *sha1 = malloc(sha1_len);
    if (sha1 != NULL) {
      if (rexmpp_digest_buffer(REXMPP_DIGEST_SHA1,
                               str, strlen(str),
                               sha1, sha1_len) == 0)
        {
          rexmpp_base64_to(sha1, sha1_len, &out, &out_len);
        }
      free(sha1);
    }
    free(str);
  }
  return out;
}

rexmpp_xml_t *rexmpp_find_event (rexmpp_t *s,
                                 const char *from,
                                 const char *node,
                                 rexmpp_xml_t **prev_event)
{
  rexmpp_xml_t *prev, *cur;
  for (prev = NULL, cur = s->roster_events;
       cur != NULL;
       prev = cur, cur = cur->next) {
    const char *cur_from = rexmpp_xml_find_attr_val(cur, "from");
    if (cur_from == NULL) {
      continue;
    }
    rexmpp_xml_t *cur_event =
      rexmpp_xml_find_child(cur,
                            "http://jabber.org/protocol/pubsub#event",
                            "event");
    rexmpp_xml_t *cur_items =
      rexmpp_xml_find_child(cur_event,
                            "http://jabber.org/protocol/pubsub#event",
                            "items");
    if (cur_items == NULL) {
      continue;
    }
    const char *cur_node = rexmpp_xml_find_attr_val(cur_items, "node");
    if (cur_node == NULL) {
      continue;
    }
    int match = (strcmp(cur_from, from) == 0 && strcmp(cur_node, node) == 0);
    if (match) {
      if (prev_event != NULL) {
        *prev_event = prev;
      }
      return cur;
    }
  }
  return NULL;
}

/* https://docs.modernxmpp.org/client/design/#names */
char *rexmpp_get_name (rexmpp_t *s, const char *jid_str) {
  struct rexmpp_jid jid;
  if (rexmpp_jid_parse(jid_str, &jid) != 0) {
    return NULL;
  }
  if (s->manage_roster) {
    rexmpp_xml_t *roster_item = rexmpp_roster_find_item(s, jid.bare, NULL);
    if (roster_item != NULL) {
      const char *name = rexmpp_xml_find_attr_val(roster_item, "name");
      if (name != NULL) {
        return strdup(name);
      }
    }
    if (s->track_roster_events) {
      rexmpp_xml_t *elem =
        rexmpp_find_event(s, jid.bare, "http://jabber.org/protocol/nick", NULL);
      if (elem != NULL) {
        rexmpp_xml_t *event =
          rexmpp_xml_find_child(elem,
                                "http://jabber.org/protocol/pubsub#event",
                                "event");
        rexmpp_xml_t *items =
          rexmpp_xml_find_child(event,
                                "http://jabber.org/protocol/pubsub#event",
                                "items");
        rexmpp_xml_t *item =
          rexmpp_xml_find_child(items,
                                "http://jabber.org/protocol/pubsub#event",
                                "item");
        if (item != NULL) {
          rexmpp_xml_t *nick =
            rexmpp_xml_find_child(item,
                                  "http://jabber.org/protocol/nick",
                                  "nick");
          if (nick != NULL &&
              nick->type == REXMPP_XML_ELEMENT &&
              nick->alt.elem.children != NULL &&
              nick->alt.elem.children->type == REXMPP_XML_TEXT) {
            return strdup(rexmpp_xml_text_child(nick));
          }
        }
      }
    }
  }
  if (jid.local[0] != '\0') {
    return strdup(jid.local);
  }
  return strdup(jid.bare);
}

rexmpp_xml_t *rexmpp_xml_feature (const char *var) {
  rexmpp_xml_t *feature = rexmpp_xml_new_elem("feature", NULL);
  rexmpp_xml_add_attr(feature, "var", var);
  return feature;
}

void rexmpp_disco_find_feature_cb (rexmpp_t *s,
                                   void *ptr,
                                   rexmpp_xml_t *request,
                                   rexmpp_xml_t *response,
                                   int success)
{
  struct rexmpp_feature_search *search = ptr;
  if (! success) {
    const char *to = rexmpp_xml_find_attr_val(request, "to");
    rexmpp_xml_t *query = request->alt.elem.children;
    rexmpp_log(s, LOG_ERR, "Failed to query %s for %s.", to, query->alt.elem.qname.namespace);
  } else if (! search->found) {
    rexmpp_xml_t *query = rexmpp_xml_first_elem_child(response);
    if (rexmpp_xml_match(query, "http://jabber.org/protocol/disco#info",
                         "query")) {
      rexmpp_xml_t *child = rexmpp_xml_first_elem_child(query);
      while (child != NULL && (! search->found)) {
        if (rexmpp_xml_match(child, "http://jabber.org/protocol/disco#info",
                             "feature")) {
          const char *var = rexmpp_xml_find_attr_val(child, "var");
          if (var != NULL) {
            if (strcmp(var, search->feature_var) == 0) {
              search->cb(s, search->cb_data, request, response, success);
              search->found = 1;
            }
          }
        }
        child = rexmpp_xml_next_elem_sibling(child);
      }
      if ((! search->found) && (search->max_requests > 0)) {
        /* Still not found, request items */
        const char *jid = rexmpp_xml_find_attr_val(request, "to");
        if (jid != NULL) {
          search->pending++;
          search->max_requests--;
          rexmpp_xml_t *query =
            rexmpp_xml_new_elem("query",
                                "http://jabber.org/protocol/disco#items");
          rexmpp_cached_iq_new(s, "get", jid, query,
                               rexmpp_disco_find_feature_cb,
                               search, search->fresh);
        }
      }
    } else if (rexmpp_xml_match(query,
                                "http://jabber.org/protocol/disco#items",
                                "query")) {
      rexmpp_xml_t *child = rexmpp_xml_first_elem_child(query);
      while (child != NULL && (search->max_requests > 0)) {
        if (rexmpp_xml_match(child, "http://jabber.org/protocol/disco#items",
                             "item")) {
          const char *jid = rexmpp_xml_find_attr_val(child, "jid");
          if (jid != NULL) {
            search->pending++;
            search->max_requests--;
            rexmpp_xml_t *query =
              rexmpp_xml_new_elem("query",
                                  "http://jabber.org/protocol/disco#info");
            rexmpp_cached_iq_new(s, "get", jid, query,
                                 rexmpp_disco_find_feature_cb,
                                 search, search->fresh);
          }
        }
        child = rexmpp_xml_next_elem_sibling(child);
      }
    }
  }
  search->pending--;
  if (search->pending == 0) {
    if (! search->found) {
      search->cb(s, search->cb_data, NULL, NULL, 0);
    }
    free(search);
  }
}

rexmpp_err_t
rexmpp_disco_find_feature (rexmpp_t *s,
                           const char *jid,
                           const char *feature_var,
                           rexmpp_iq_callback_t cb,
                           void *cb_data,
                           int fresh,
                           int max_requests)
{
  struct rexmpp_feature_search *search =
    malloc(sizeof(struct rexmpp_feature_search));
  if (search == NULL) {
    return REXMPP_E_MALLOC;
  }
  search->max_requests = max_requests - 1;
  search->found = 0;
  search->pending = 1;
  search->cb = cb;
  search->cb_data = cb_data;
  search->fresh = fresh;
  search->feature_var = feature_var;
  rexmpp_xml_t *query =
    rexmpp_xml_new_elem("query", "http://jabber.org/protocol/disco#info");
  if (jid == NULL) {
    jid = s->initial_jid.domain;
  }
  return rexmpp_cached_iq_new(s, "get", jid, query,
                              rexmpp_disco_find_feature_cb, search, fresh);
}

rexmpp_xml_t *rexmpp_disco_info (rexmpp_t *s) {
  if (s->disco_info != NULL) {
    return s->disco_info;
  }
  rexmpp_xml_t *prev = NULL, *cur;
  /* There must be at least one identity, so filling in somewhat
     sensible defaults. A basic client may leave them be, while an
     advanced one would adjust and/or extend them. */
  s->disco_info = rexmpp_xml_new_elem("identity", NULL);
  rexmpp_xml_add_attr(s->disco_info, "category", "client");
  rexmpp_xml_add_attr(s->disco_info, "type", s->client_type);
  rexmpp_xml_add_attr(s->disco_info, "name", s->client_name);
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
  if (s->enable_jingle) {
    cur = rexmpp_xml_feature("urn:xmpp:jingle:1");
    prev->next = cur;
    prev = cur;
    cur = rexmpp_xml_feature("urn:xmpp:jingle:apps:file-transfer:5");
    prev->next = cur;
    prev = cur;
    cur = rexmpp_xml_feature("urn:xmpp:jingle:transports:ibb:1");
    prev->next = cur;
    prev = cur;
#ifdef ENABLE_CALLS
    cur = rexmpp_xml_feature("urn:xmpp:jingle:apps:dtls:0");
    prev->next = cur;
    prev = cur;
    cur = rexmpp_xml_feature("urn:xmpp:jingle:transports:ice-udp:1");
    prev->next = cur;
    prev = cur;
    cur = rexmpp_xml_feature("urn:xmpp:jingle:apps:rtp:1");
    prev->next = cur;
    prev = cur;
    cur = rexmpp_xml_feature("urn:xmpp:jingle:apps:rtp:audio");
    prev->next = cur;
    prev = cur;
#endif
  }
  cur = rexmpp_xml_feature("urn:xmpp:ping");
  prev->next = cur;
  prev = cur;
  return s->disco_info;
}

struct rexmpp_xml_parser_handlers sax = {
  (rexmpp_xml_parser_element_start)rexmpp_sax_start_elem_ns,
  (rexmpp_xml_parser_element_end)rexmpp_sax_end_elem_ns,
  (rexmpp_xml_parser_characters)rexmpp_sax_characters
};

rexmpp_err_t rexmpp_init (rexmpp_t *s,
                          const char *jid,
                          log_function_t log_func)
{
  int err;

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
  s->manage_roster = 1;
  s->roster_cache_file = NULL;
  s->track_roster_presence = 1;
  s->track_roster_events = 1;
  s->nick_notifications = 1;
#ifdef HAVE_GPGME
  s->retrieve_openpgp_keys = 1;
#else
  s->retrieve_openpgp_keys = 0;
#endif
  s->autojoin_bookmarked_mucs = 1;
  s->tls_policy = REXMPP_TLS_REQUIRE;
  s->enable_jingle = 1;
  s->client_name = PACKAGE_NAME;
  s->client_type = "console";
  s->client_version = PACKAGE_VERSION;
  s->local_address = NULL;
  s->jingle_prefer_rtcp_mux = 1;
  s->path_mtu_discovery = -1;
  s->send_buffer = NULL;
  s->send_queue = NULL;
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
  s->iq_cache = NULL;
  s->reconnect_number = 0;
  s->next_reconnect_time.tv_sec = 0;
  s->next_reconnect_time.tv_nsec = 0;
  s->initial_jid.full[0] = '\0';
  s->assigned_jid.full[0] = '\0';
  s->stanza_queue_size = 1024;
  s->send_queue_size = 1024;
  s->iq_queue_size = 1024;
  s->iq_cache_size = 1024;
  s->max_jingle_sessions = 1024;
  s->x509_cert_file = NULL;
  s->x509_key_file = NULL;
  s->x509_trust_file = NULL;
  s->log_function = log_func;
  s->sasl_property_cb = NULL;
  s->xml_in_cb = NULL;
  s->xml_out_cb = NULL;
  s->roster_modify_cb = NULL;
  s->console_print_cb = NULL;
  s->ping_delay = 600;
  s->ping_requested = 0;
  s->last_network_activity.tv_sec = 0;
  s->last_network_activity.tv_nsec = 0;
  s->disco_info = NULL;

  s->jingle_rtp_description =
    rexmpp_xml_new_elem("description", "urn:xmpp:jingle:apps:rtp:1");
  rexmpp_xml_add_attr(s->jingle_rtp_description, "media", "audio");
  rexmpp_xml_t *pl_type;

#ifdef HAVE_OPUS
  pl_type = rexmpp_xml_new_elem("payload-type", "urn:xmpp:jingle:apps:rtp:1");
  rexmpp_xml_add_attr(pl_type, "id", "97");
  rexmpp_xml_add_attr(pl_type, "name", "opus");
  rexmpp_xml_add_attr(pl_type, "clockrate", "48000");
  rexmpp_xml_add_attr(pl_type, "channels", "2");
  rexmpp_xml_add_child(s->jingle_rtp_description, pl_type);
#endif

  pl_type = rexmpp_xml_new_elem("payload-type", "urn:xmpp:jingle:apps:rtp:1");
  rexmpp_xml_add_attr(pl_type, "id", "0");
  rexmpp_xml_add_attr(pl_type, "name", "PCMU");
  rexmpp_xml_add_attr(pl_type, "clockrate", "8000");
  rexmpp_xml_add_attr(pl_type, "channels", "1");
  rexmpp_xml_add_child(s->jingle_rtp_description, pl_type);

  pl_type = rexmpp_xml_new_elem("payload-type", "urn:xmpp:jingle:apps:rtp:1");
  rexmpp_xml_add_attr(pl_type, "id", "8");
  rexmpp_xml_add_attr(pl_type, "name", "PCMA");
  rexmpp_xml_add_attr(pl_type, "clockrate", "8000");
  rexmpp_xml_add_attr(pl_type, "channels", "1");
  rexmpp_xml_add_child(s->jingle_rtp_description, pl_type);

  if (jid == NULL) {
    rexmpp_log(s, LOG_CRIT, "No initial JID is provided.");
    return REXMPP_E_JID;
  }

  if (rexmpp_jid_parse(jid, &(s->initial_jid))) {
    rexmpp_log(s, LOG_CRIT, "Failed to parse the initial JID.");
    return REXMPP_E_JID;
  }
  if (! rexmpp_jid_check(&s->initial_jid)) {
    rexmpp_log(s, LOG_CRIT, "An invalid initial JID is provided.");
    return REXMPP_E_JID;
  }

#ifdef HAVE_GCRYPT
  if (! gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
    rexmpp_log(s, LOG_DEBUG, "Initializing libgcrypt");
    if (gcry_check_version(NULL) == NULL) {
      rexmpp_log(s, LOG_CRIT, "Failed to initialize libgcrypt");
      return REXMPP_E_OTHER;
    }
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
  }
#endif

  s->xml_parser = rexmpp_xml_parser_new(&sax, s);

  if (s->xml_parser == NULL) {
    rexmpp_log(s, LOG_CRIT, "Failed to create an XML parser context.");
    return REXMPP_E_XML;
  }

  if (rexmpp_dns_ctx_init(s)) {
    rexmpp_xml_parser_free(s->xml_parser);
    return REXMPP_E_DNS;
  }

  if (rexmpp_tls_init(s)) {
    rexmpp_dns_ctx_deinit(s);
    rexmpp_xml_parser_free(s->xml_parser);
    return REXMPP_E_TLS;
  }

  err = rexmpp_sasl_ctx_init(s);
  if (err) {
    rexmpp_tls_deinit(s);
    rexmpp_dns_ctx_deinit(s);
    rexmpp_xml_parser_free(s->xml_parser);
    return REXMPP_E_SASL;
  }

  if (rexmpp_jingle_init(s)) {
    rexmpp_sasl_ctx_deinit(s);
    rexmpp_tls_deinit(s);
    rexmpp_dns_ctx_deinit(s);
    rexmpp_xml_parser_free(s->xml_parser);
  }

#ifdef HAVE_GPGME
  gpgme_check_version(NULL);
  err = gpgme_new(&(s->pgp_ctx));
  if (gpg_err_code(err) != GPG_ERR_NO_ERROR) {
    rexmpp_log(s, LOG_CRIT, "gpgme initialisation error: %s",
               gpgme_strerror(err));
    rexmpp_sasl_ctx_deinit(s);
    rexmpp_tls_deinit(s);
    rexmpp_dns_ctx_deinit(s);
    rexmpp_jingle_stop(s);
    rexmpp_xml_parser_free(s->xml_parser);
    return REXMPP_E_PGP;
  }
#else
  s->pgp_ctx = NULL;
#endif
#ifdef HAVE_CURL
  if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
    rexmpp_log(s, LOG_CRIT, "Failed to initialize curl");
  }
  s->curl_multi = curl_multi_init();
  if (s->curl_multi == NULL) {
    rexmpp_log(s, LOG_CRIT, "Failed to initialize curl_multi");
    /* todo: free other structures and fail */
  }
#else
  s->curl_multi = NULL;
#endif

  return REXMPP_SUCCESS;
}

/* Prepares for a reconnect: cleans up some things (e.g., SASL and TLS
   structures), but keeps others (e.g., stanza queue and stream ID,
   since we may resume the stream afterwards). */
void rexmpp_cleanup (rexmpp_t *s) {
  rexmpp_tls_cleanup(s);
  s->tls_state = REXMPP_TLS_INACTIVE;
  if (s->sasl_state != REXMPP_SASL_INACTIVE) {
    rexmpp_sasl_ctx_cleanup(s);
    s->sasl_state = REXMPP_SASL_INACTIVE;
  }
  if (s->tcp_state == REXMPP_TCP_CONNECTING) {
    int sock = rexmpp_tcp_conn_finish(&s->server_connection);
    if (sock != -1) {
      rexmpp_log(s, LOG_DEBUG, "TCP disconnected");
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
    rexmpp_xml_free(s->stream_features);
    s->stream_features = NULL;
  }
  if (s->send_queue != NULL) {
    rexmpp_xml_free_list(s->send_queue);
    s->send_queue = NULL;
  }
  if (s->current_element_root != NULL) {
    rexmpp_xml_free_list(s->current_element_root);
    s->current_element_root = NULL;
    s->current_element = NULL;
  }
  if (s->input_queue != NULL) {
    rexmpp_xml_free_list(s->input_queue);
    s->input_queue = NULL;
    s->input_queue_last = NULL;
  }
  if (s->server_srv != NULL) {
    rexmpp_dns_result_free(s->server_srv);
    s->server_srv = NULL;
    s->server_srv_cur = -1;
  }
  if (s->server_srv_tls != NULL) {
    rexmpp_dns_result_free(s->server_srv_tls);
    s->server_srv_tls = NULL;
    s->server_srv_tls_cur = -1;
  }
  s->sm_state = REXMPP_SM_INACTIVE;
  s->ping_requested = 0;
}

void rexmpp_iq_finish (rexmpp_t *s,
                       rexmpp_iq_t *iq,
                       int success,
                       rexmpp_xml_t *response)
{
  if (iq->cb != NULL) {
    iq->cb(s, iq->cb_data, iq->request, response, success);
  }
  rexmpp_xml_free(iq->request);
  free(iq);
}

/* Frees the things that persist through reconnects. */
void rexmpp_done (rexmpp_t *s) {
  rexmpp_jingle_stop(s);
  rexmpp_cleanup(s);
#ifdef HAVE_CURL
  curl_multi_cleanup(s->curl_multi);
  curl_global_cleanup();
#endif
#ifdef HAVE_GPGME
  gpgme_release(s->pgp_ctx);
#endif
  rexmpp_sasl_ctx_deinit(s);
  rexmpp_tls_deinit(s);
  rexmpp_dns_ctx_deinit(s);
  rexmpp_xml_parser_free(s->xml_parser);
  if (s->jingle_rtp_description != NULL) {
    rexmpp_xml_free(s->jingle_rtp_description);
    s->jingle_rtp_description = NULL;
  }
  if (s->stream_id != NULL) {
    free(s->stream_id);
    s->stream_id = NULL;
  }
  if (s->roster_items != NULL) {
    rexmpp_xml_free_list(s->roster_items);
    s->roster_items = NULL;
  }
  if (s->roster_presence != NULL) {
    rexmpp_xml_free_list(s->roster_presence);
    s->roster_presence = NULL;
  }
  if (s->roster_events != NULL) {
    rexmpp_xml_free_list(s->roster_events);
    s->roster_events = NULL;
  }
  if (s->roster_ver != NULL) {
    free(s->roster_ver);
    s->roster_ver = NULL;
  }
  if (s->disco_info != NULL) {
    rexmpp_xml_free_list(s->disco_info);
    s->disco_info = NULL;
  }
  if (s->stanza_queue != NULL) {
    rexmpp_xml_free_list(s->stanza_queue);
    s->stanza_queue = NULL;
  }
  while (s->active_iq != NULL) {
    rexmpp_iq_t *next = s->active_iq->next;
    rexmpp_iq_t *iq = s->active_iq;
    s->active_iq = next;
    rexmpp_iq_finish(s, iq, 0, NULL);
  }
  if (s->iq_cache != NULL) {
    rexmpp_xml_free_list(s->iq_cache);
    s->iq_cache = NULL;
  }
}

void rexmpp_schedule_reconnect (rexmpp_t *s) {
  if (s->stream_state == REXMPP_STREAM_CLOSE_REQUESTED ||
      s->stream_state == REXMPP_STREAM_CLOSING) {
    /* Don't schedule a reconnect if a reconnect-causing condition
       happened during closing. */
    return;
  }
  if (s->reconnect_number == 0) {
    rexmpp_random_buf((char*)&s->reconnect_seconds, sizeof(time_t));
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
  clock_gettime(CLOCK_MONOTONIC, &(s->next_reconnect_time));
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

rexmpp_xml_t *rexmpp_xml_set_delay (rexmpp_t *s, rexmpp_xml_t *node) {
  if (rexmpp_xml_find_child (node, NULL, "delay")) {
    return node;
  }
  char buf[42];
  time_t t = time(NULL);
  struct tm utc_time;
  gmtime_r(&t, &utc_time);
  strftime(buf, 42, "%FT%TZ", &utc_time);
  rexmpp_xml_t *delay = rexmpp_xml_new_elem("delay", NULL);
  rexmpp_xml_add_child(node, delay);
  rexmpp_xml_add_attr(delay, "stamp", buf);
  if (s != NULL && s->assigned_jid.full[0]) {
    rexmpp_xml_add_attr(delay, "from", s->assigned_jid.full);
  }
  return node;
}

rexmpp_err_t rexmpp_send_start (rexmpp_t *s, const void *data, size_t data_len)
{
  int sasl_err;
  if (s->send_buffer != NULL) {
    rexmpp_log(s, LOG_CRIT, "send buffer is not empty: %s", s->send_buffer);
    return REXMPP_E_SEND_BUFFER_NOT_EMPTY;
  }
  if (s->sasl_state == REXMPP_SASL_ACTIVE) {
    sasl_err = rexmpp_sasl_encode (s, data, data_len,
                                   &(s->send_buffer), &(s->send_buffer_len));
    if (sasl_err) {
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
  ssize_t ret;
  rexmpp_tls_err_t err;
  int tls_was_active;
  while (1) {
    tls_was_active = (s->tls_state == REXMPP_TLS_ACTIVE);
    if (tls_was_active) {
      err = rexmpp_tls_send (s,
                             s->tls,
                             s->send_buffer,
                             s->send_buffer_len,
                             &ret);
    } else {
      ret = send (s->server_socket,
                  s->send_buffer + s->send_buffer_sent,
                  s->send_buffer_len - s->send_buffer_sent,
                  0);
    }
    if (ret > 0) {
      clock_gettime(CLOCK_MONOTONIC, &(s->last_network_activity));
      s->send_buffer_sent += ret;
      if (s->send_buffer_sent == s->send_buffer_len) {
        free(s->send_buffer);
        s->send_buffer = NULL;
        if (s->send_queue != NULL) {
          rexmpp_xml_t *node = s->send_queue;
          char *buf = rexmpp_xml_serialize(node, 0);
          ret = rexmpp_send_start(s, buf, strlen(buf));
          free(buf);
          if (ret != REXMPP_SUCCESS) {
            return ret;
          }
          s->send_queue = s->send_queue->next;
          rexmpp_xml_free(node);
        } else {
          return REXMPP_SUCCESS;
        }
      }
    } else {
      if (tls_was_active) {
        if (err != REXMPP_TLS_E_AGAIN) {
          s->tls_state = REXMPP_TLS_ERROR;
          /* Assume a TCP error for now as well. */
          rexmpp_cleanup(s);
          s->tcp_state = REXMPP_TCP_ERROR;
          rexmpp_schedule_reconnect(s);
          return REXMPP_E_AGAIN;
        }
      } else {
        if (errno != EAGAIN) {
          rexmpp_log(s, LOG_ERR, "TCP send error: %s", strerror(errno));
          rexmpp_cleanup(s);
          s->tcp_state = REXMPP_TCP_ERROR;
          rexmpp_schedule_reconnect(s);
          return REXMPP_E_AGAIN;
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

rexmpp_err_t rexmpp_send (rexmpp_t *s, rexmpp_xml_t *node)
{
  int need_ack = 0;
  int ret;

  if (s->xml_out_cb != NULL && s->xml_out_cb(s, node) == 1) {
    rexmpp_xml_free(node);
    rexmpp_log(s, LOG_WARNING, "Message sending was cancelled by xml_out_cb.");
    return REXMPP_E_CANCELLED;
  }

  if (rexmpp_xml_siblings_count(s->send_queue) >= s->send_queue_size) {
    rexmpp_xml_free(node);
    rexmpp_log(s, LOG_ERR, "The send queue is full, not sending.");
    return REXMPP_E_SEND_QUEUE_FULL;
  }

  rexmpp_console_on_send(s, node);

  if (rexmpp_xml_is_stanza(node)) {
    if (s->sm_state == REXMPP_SM_ACTIVE) {
      if (s->stanzas_out_count >=
          s->stanza_queue_size + s->stanzas_out_acknowledged) {
        rexmpp_xml_free(node);
        rexmpp_log(s, LOG_ERR, "The stanza queue is full, not sending.");
        return REXMPP_E_STANZA_QUEUE_FULL;
      }
      need_ack = 1;
      rexmpp_xml_t *queued_stanza =
        rexmpp_xml_set_delay(s, rexmpp_xml_clone(node));
      if (s->stanza_queue == NULL) {
        s->stanza_queue = queued_stanza;
      } else {
        rexmpp_xml_t *last = s->stanza_queue;
        while (last->next != NULL) {
          last = last->next;
        }
        last->next = queued_stanza;
      }
    }
    if (s->sm_state != REXMPP_SM_INACTIVE) {
      s->stanzas_out_count++;
    }
  }

  if (s->send_buffer == NULL) {
    char *buf = rexmpp_xml_serialize(node, 0);
    ret = rexmpp_send_raw(s, buf, strlen(buf));
    free(buf);
    rexmpp_xml_free(node);
    if (ret != REXMPP_SUCCESS && ret != REXMPP_E_AGAIN) {
      return ret;
    }
  } else {
    if (s->send_queue == NULL) {
      s->send_queue = node;
    } else {
      rexmpp_xml_t *last = s->send_queue;
      while (last->next != NULL) {
        last = last->next;
      }
      last->next = node;
    }
    ret = REXMPP_E_AGAIN;
  }
  if (need_ack) {
    return rexmpp_sm_send_req(s);
  }
  return ret;
}

void rexmpp_iq_reply (rexmpp_t *s,
                      rexmpp_xml_t *req,
                      const char *type,
                      rexmpp_xml_t *payload)
{
  rexmpp_xml_t *iq_stanza = rexmpp_xml_new_elem("iq", "jabber:client");
  rexmpp_xml_add_attr(iq_stanza, "type", type);
  const char *id = rexmpp_xml_find_attr_val(req, "id");
  if (id != NULL) {
    rexmpp_xml_add_attr(iq_stanza, "id", id);
  }
  const char *to = rexmpp_xml_find_attr_val(req, "from");
  if (to != NULL) {
    rexmpp_xml_add_attr(iq_stanza, "to", to);
  }
  if (s->assigned_jid.full[0]) {
    rexmpp_xml_add_attr(iq_stanza, "from", s->assigned_jid.full);
  }
  if (payload != NULL) {
    rexmpp_xml_add_child(iq_stanza, payload);
  }
  rexmpp_send(s, iq_stanza);
}

rexmpp_err_t rexmpp_iq_new (rexmpp_t *s,
                            const char *type,
                            const char *to,
                            rexmpp_xml_t *payload,
                            rexmpp_iq_callback_t cb,
                            void *cb_data)
{
  unsigned int i;
  rexmpp_iq_t *prev = NULL, *last = s->active_iq;
  for (i = 0; last != NULL && last->next != NULL; i++) {
    prev = last;
    last = last->next;
  }
  if (i >= s->iq_queue_size && s->iq_queue_size > 0) {
    assert(prev != NULL);
    assert(last != NULL);
    rexmpp_log(s, LOG_WARNING,
               "The IQ queue limit is reached, giving up on the oldest IQ.");
    prev->next = NULL;
    rexmpp_iq_finish(s, last, 0, NULL);
  }

  rexmpp_xml_t *iq_stanza =
    rexmpp_xml_new_elem("iq", "jabber:client");
  rexmpp_xml_add_id(iq_stanza);
  rexmpp_xml_add_attr(iq_stanza, "type", type);
  if (to != NULL) {
    rexmpp_xml_add_attr(iq_stanza, "to", to);
  }
  if (s->assigned_jid.full[0]) {
    rexmpp_xml_add_attr(iq_stanza, "from", s->assigned_jid.full);
  }
  rexmpp_xml_add_child(iq_stanza, payload);
  rexmpp_iq_t *iq = malloc(sizeof(rexmpp_iq_t));
  if (iq == NULL) {
    return REXMPP_E_MALLOC;
  }
  iq->request = rexmpp_xml_clone(iq_stanza);
  iq->cb = cb;
  iq->cb_data = cb_data;
  iq->next = s->active_iq;
  s->active_iq = iq;
  return rexmpp_send(s, iq_stanza);
}

void rexmpp_iq_cache_cb (rexmpp_t *s,
                         void *cb_data,
                         rexmpp_xml_t *request,
                         rexmpp_xml_t *response,
                         int success)
{
  if (success && response != NULL) {
    rexmpp_xml_t *prev_last = NULL, *last = NULL, *ciq = s->iq_cache;
    uint32_t size = 0;
    while (ciq != NULL && ciq->next != NULL) {
      prev_last = last;
      last = ciq;
      size++;
      ciq = ciq->next->next;
    }
    if (size >= s->iq_queue_size && prev_last != NULL) {
      rexmpp_xml_free(last->next);
      rexmpp_xml_free(last);
      prev_last->next->next = NULL;
    }
    rexmpp_xml_t *req = rexmpp_xml_clone(request);
    rexmpp_xml_t *resp = rexmpp_xml_clone(response);
    req->next = resp;
    resp->next = s->iq_cache;
    s->iq_cache = req;
  }
  struct rexmpp_iq_cacher *cacher = cb_data;
  if (cacher->cb != NULL) {
    cacher->cb(s, cacher->cb_data, request, response, success);
  }
  free(cacher);
}

rexmpp_err_t rexmpp_cached_iq_new (rexmpp_t *s,
                                   const char *type,
                                   const char *to,
                                   rexmpp_xml_t *payload,
                                   rexmpp_iq_callback_t cb,
                                   void *cb_data,
                                   int fresh)
{
  if (! fresh) {
    rexmpp_xml_t *ciq = s->iq_cache;
    while (ciq != NULL && ciq->next != NULL) {
      rexmpp_xml_t *ciq_pl = ciq->alt.elem.children;
      const char *ciq_type = rexmpp_xml_find_attr_val(ciq, "type");
      const char *ciq_to = rexmpp_xml_find_attr_val(ciq, "to");
      int matches = (rexmpp_xml_eq(ciq_pl, payload) &&
                     strcmp(ciq_type, type) == 0 &&
                     strcmp(ciq_to, to) == 0);
      if (matches) {
        rexmpp_xml_free(payload);
        if (cb != NULL) {
          cb(s, cb_data, ciq, ciq->next, 1);
        }
        return REXMPP_SUCCESS;
      }
      ciq = ciq->next->next;
    }
  }
  struct rexmpp_iq_cacher *cacher = malloc(sizeof(struct rexmpp_iq_cacher));
  cacher->cb = cb;
  cacher->cb_data = cb_data;
  return rexmpp_iq_new(s, type, to, payload, rexmpp_iq_cache_cb, cacher);
}


rexmpp_err_t rexmpp_sm_ack (rexmpp_t *s) {
  char buf[11];
  rexmpp_xml_t *ack = rexmpp_xml_new_elem("a", "urn:xmpp:sm:3");
  snprintf(buf, 11, "%u", s->stanzas_in_count);
  rexmpp_xml_add_attr(ack, "h", buf);
  return rexmpp_send(s, ack);
}

rexmpp_err_t rexmpp_sm_send_req (rexmpp_t *s) {
  rexmpp_xml_t *req = rexmpp_xml_new_elem("r", "urn:xmpp:sm:3");
  return rexmpp_send(s, req);
}

rexmpp_err_t rexmpp_process_element (rexmpp_t *s, rexmpp_xml_t *elem);

rexmpp_err_t rexmpp_recv (rexmpp_t *s) {
  char chunk_raw[4096], *chunk;
  size_t chunk_len;
  ssize_t chunk_raw_len;
  int sasl_err;
  rexmpp_tls_err_t recv_err;
  rexmpp_err_t err = REXMPP_SUCCESS;
  int tls_was_active;
  /* Loop here in order to consume data from TLS buffers, which
     wouldn't show up on select(). */
  do {
    tls_was_active = (s->tls_state == REXMPP_TLS_ACTIVE);
    if (tls_was_active) {
      recv_err = rexmpp_tls_recv(s, s->tls, chunk_raw, 4096, &chunk_raw_len);
    } else {
      chunk_raw_len = recv(s->server_socket, chunk_raw, 4096, 0);
    }
    if (chunk_raw_len > 0) {
      clock_gettime(CLOCK_MONOTONIC, &(s->last_network_activity));
      if (s->sasl_state == REXMPP_SASL_ACTIVE) {
        sasl_err = rexmpp_sasl_decode(s, chunk_raw, chunk_raw_len,
                                      &chunk, &chunk_len);
        if (sasl_err) {
          s->sasl_state = REXMPP_SASL_ERROR;
          return REXMPP_E_SASL;
        }
      } else {
        chunk = chunk_raw;
        chunk_len = chunk_raw_len;
      }
      rexmpp_xml_parser_feed(s->xml_parser, chunk, chunk_len, 0);
      if (chunk != chunk_raw && chunk != NULL) {
        free(chunk);
      }
      chunk = NULL;

      rexmpp_xml_t *elem;
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
      rexmpp_xml_free_list(s->input_queue);
      s->input_queue = NULL;
      s->input_queue_last = NULL;
      if (err != REXMPP_SUCCESS && err != REXMPP_E_AGAIN) {
        return err;
      }
    } else if (chunk_raw_len == 0) {
      if (tls_was_active) {
        s->tls_state = REXMPP_TLS_CLOSED;
        rexmpp_log(s, LOG_DEBUG, "TLS disconnected");
      }
      rexmpp_log(s, LOG_DEBUG, "TCP disconnected");
      rexmpp_cleanup(s);
      if (s->stream_state == REXMPP_STREAM_READY ||
          s->stream_state == REXMPP_STREAM_ERROR_RECONNECT) {
        s->tcp_state = REXMPP_TCP_NONE;
        rexmpp_schedule_reconnect(s);
        return REXMPP_E_AGAIN;
      } else {
        s->tcp_state = REXMPP_TCP_CLOSED;
      }
    } else {
      if (tls_was_active) {
        if (recv_err != REXMPP_TLS_E_AGAIN) {
          s->tls_state = REXMPP_TLS_ERROR;
          /* Assume a TCP error for now as well. */
          rexmpp_cleanup(s);
          s->tcp_state = REXMPP_TCP_ERROR;
          rexmpp_schedule_reconnect(s);
          return REXMPP_E_AGAIN;
        }
      } else if (errno != EAGAIN) {
        rexmpp_log(s, LOG_ERR, "TCP recv error: %s", strerror(errno));
        rexmpp_cleanup(s);
        s->tcp_state = REXMPP_TCP_ERROR;
        rexmpp_schedule_reconnect(s);
        return REXMPP_E_AGAIN;
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
                              rexmpp_tcp_conn_init(s,
                                                   &s->server_connection,
                                                   s->server_host,
                                                   s->server_port));
  } else {
    rexmpp_log(s, LOG_DEBUG, "Connecting to %s:%u via %s:%u",
               s->server_host, s->server_port,
               s->socks_host, s->socks_port);
    return rexmpp_process_conn_err(s,
                                   rexmpp_tcp_conn_init(s,
                                                        &s->server_connection,
                                                        s->socks_host,
                                                        s->socks_port));
  }
}

rexmpp_err_t rexmpp_try_next_host (rexmpp_t *s) {
  rexmpp_dns_result_t *cur_result;
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

  s->server_active_srv = (rexmpp_dns_srv_t *)cur_result->data[cur_number];

  s->server_host = s->server_active_srv->target;
  s->server_port = s->server_active_srv->port;
  return rexmpp_start_connecting(s);
}

rexmpp_err_t
rexmpp_process_tls_conn_err (rexmpp_t *s,
                             rexmpp_tls_err_t err)
{
  if (err == REXMPP_TLS_E_OTHER) {
    s->tls_state = REXMPP_TLS_ERROR;
    rexmpp_cleanup(s);
    rexmpp_schedule_reconnect(s);
    return REXMPP_E_AGAIN;
  } else if (err == REXMPP_TLS_SUCCESS) {
    rexmpp_log(s, LOG_DEBUG, "A TLS connection is established");
    s->tls_state = REXMPP_TLS_ACTIVE;
    if (s->stream_state == REXMPP_STREAM_NONE) {
      /* It's a direct TLS connection, so open a stream after
         connecting. */
      return rexmpp_stream_open(s);
    } else {
      /* A STARTTLS connection, restart the stream. */
      s->xml_parser = rexmpp_xml_parser_reset(s->xml_parser);
      return rexmpp_stream_open(s);
    }
  } else {
    s->tls_state = REXMPP_TLS_HANDSHAKE;
    return REXMPP_E_AGAIN;
  }
}

rexmpp_err_t rexmpp_connected_to_server (rexmpp_t *s) {
  s->tcp_state = REXMPP_TCP_CONNECTED;
  rexmpp_log(s, LOG_INFO,
             "Connected to the server, the used address record was %s",
             s->server_socket_dns_secure ? "secure" : "not secure");
  s->reconnect_number = 0;
  s->xml_parser = rexmpp_xml_parser_reset(s->xml_parser);
  if (s->tls_state == REXMPP_TLS_AWAITING_DIRECT) {
    return rexmpp_process_tls_conn_err(s, rexmpp_tls_connect(s));
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

void rexmpp_srv_cb (rexmpp_t *s,
                    void *ptr,
                    rexmpp_dns_result_t *result)
{
  char *type = ptr;
  if (result != NULL) {
    rexmpp_log(s,
               result->secure ? LOG_DEBUG : LOG_WARNING,
               "Resolved a %s SRV record (%s)",
               type, result->secure ? "secure" : "not secure");
    if (strncmp("xmpp", type, 5) == 0) {
      s->server_srv = result;
    } else {
      s->server_srv_tls = result;
    }
  }
  if (s->resolver_state == REXMPP_RESOLVER_SRV) {
    s->resolver_state = REXMPP_RESOLVER_SRV_2;
  } else if (s->resolver_state == REXMPP_RESOLVER_SRV_2) {
    s->resolver_state = REXMPP_RESOLVER_READY;
  }
}

/* Should be called after reconnect, and after rexmpp_sm_handle_ack in
   case of resumption. */
rexmpp_err_t rexmpp_resend_stanzas (rexmpp_t *s) {
  uint32_t i, count;
  rexmpp_err_t ret = REXMPP_SUCCESS;
  rexmpp_xml_t *sq;
  count = s->stanzas_out_count - s->stanzas_out_acknowledged;
  for (i = 0; i < count && s->stanza_queue != NULL; i++) {
    sq = s->stanza_queue->next;
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

void rexmpp_sm_handle_ack (rexmpp_t *s, rexmpp_xml_t *elem) {
  const char *h = rexmpp_xml_find_attr_val(elem, "h");
  if (h != NULL) {
    uint32_t prev_ack = s->stanzas_out_acknowledged;
    s->stanzas_out_acknowledged = strtoul(h, NULL, 10);
    rexmpp_log(s, LOG_DEBUG,
               "server acknowledged %u out of %u sent stanzas",
               s->stanzas_out_acknowledged,
               s->stanzas_out_count);
    if (s->stanzas_out_count >= s->stanzas_out_acknowledged) {
      if (prev_ack <= s->stanzas_out_acknowledged) {
        uint32_t i;
        for (i = prev_ack; i < s->stanzas_out_acknowledged; i++) {
          rexmpp_xml_t *sq = s->stanza_queue->next;
          rexmpp_xml_free(s->stanza_queue);
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
                             void *ptr,
                             rexmpp_xml_t *req,
                             rexmpp_xml_t *response,
                             int success)
{
  (void)ptr;
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
                  void *ptr,
                  rexmpp_xml_t *req,
                  rexmpp_xml_t *response,
                  int success)
{
  (void)ptr;
  (void)req;
  (void)response;
  (void)success;
  s->ping_requested = 0;
}

void rexmpp_disco_carbons_cb (rexmpp_t *s,
                              void *ptr,
                              rexmpp_xml_t *req,
                              rexmpp_xml_t *response,
                              int success) {
  (void)ptr;
  (void)req;
  (void)response;
  if (success) {
    rexmpp_xml_t *carbons_enable =
      rexmpp_xml_new_elem("enable", "urn:xmpp:carbons:2");
    s->carbons_state = REXMPP_CARBONS_NEGOTIATION;
    rexmpp_iq_new(s, "set", NULL, carbons_enable,
                  rexmpp_carbons_enabled, NULL);
  } else {
    rexmpp_log(s, LOG_WARNING, "Failed to discover the carbons feature.");
  }
}

void rexmpp_stream_is_ready(rexmpp_t *s) {
  s->stream_state = REXMPP_STREAM_READY;
  rexmpp_resend_stanzas(s);

  if (s->enable_carbons) {
    rexmpp_disco_find_feature (s, s->initial_jid.domain,
                               "urn:xmpp:carbons:2",
                               rexmpp_disco_carbons_cb,
                               NULL, 0, 1);
  }
  if (s->manage_roster) {
    if (s->roster_cache_file != NULL) {
      rexmpp_roster_cache_read(s);
    }
    rexmpp_xml_t *roster_query =
      rexmpp_xml_new_elem("query", "jabber:iq:roster");
    if (s->roster_ver != NULL) {
      rexmpp_xml_add_attr(roster_query, "ver", s->roster_ver);
    } else {
      rexmpp_xml_add_attr(roster_query, "ver", "");
    }
    rexmpp_iq_new(s, "get", NULL,
                  roster_query, rexmpp_iq_roster_get, NULL);
  }
  rexmpp_xml_t *presence =
    rexmpp_xml_new_elem("presence", "jabber:client");
  rexmpp_xml_add_id(presence);

  char *caps_hash = rexmpp_capabilities_hash(s, rexmpp_disco_info(s));
  if (caps_hash != NULL) {
    rexmpp_xml_t *c =
      rexmpp_xml_new_elem("c", "http://jabber.org/protocol/caps");
    rexmpp_xml_add_attr(c, "hash", "sha-1");
    rexmpp_xml_add_attr(c, "node", s->disco_node);
    rexmpp_xml_add_attr(c, "ver", caps_hash);
    rexmpp_xml_add_child(presence, c);
    free(caps_hash);
  }

  rexmpp_send(s, presence);
}

/* Resource binding,
   https://tools.ietf.org/html/rfc6120#section-7 */
void rexmpp_bound (rexmpp_t *s,
                   void *ptr,
                   rexmpp_xml_t *req,
                   rexmpp_xml_t *response,
                   int success)
{
  (void)ptr;
  (void)req;
  if (! success) {
    /* todo: reconnect here? */
    rexmpp_log(s, LOG_ERR, "Resource binding failed.");
    return;
  }
  /* todo: handle errors */
  rexmpp_xml_t *child = rexmpp_xml_first_elem_child(response);
  if (rexmpp_xml_match(child, "urn:ietf:params:xml:ns:xmpp-bind", "bind")) {
    rexmpp_xml_t *jid = rexmpp_xml_first_elem_child(child);
    if (rexmpp_xml_match(jid, "urn:ietf:params:xml:ns:xmpp-bind", "jid")) {
      const char *jid_str = rexmpp_xml_text_child(jid);
      rexmpp_log(s, LOG_INFO, "jid: %s", jid_str);
      rexmpp_jid_parse(jid_str, &(s->assigned_jid));
    }
    if (s->stream_id == NULL &&
        (rexmpp_xml_find_child(s->stream_features, "urn:xmpp:sm:3",
                               "sm") != NULL)) {
      /* Try to resume a stream. */
      s->sm_state = REXMPP_SM_NEGOTIATION;
      s->stream_state = REXMPP_STREAM_SM_FULL;
      rexmpp_xml_t *sm_enable =
        rexmpp_xml_new_elem("enable", "urn:xmpp:sm:3");
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
  rexmpp_xml_t *bind_cmd =
    rexmpp_xml_new_elem("bind", "urn:ietf:params:xml:ns:xmpp-bind");
  return rexmpp_iq_new(s, "set", NULL, bind_cmd, rexmpp_bound, NULL);
}

rexmpp_err_t rexmpp_process_element (rexmpp_t *s, rexmpp_xml_t *elem) {
  rexmpp_console_on_recv(s, elem);

  /* Stream negotiation,
     https://tools.ietf.org/html/rfc6120#section-4.3 */
  if (s->stream_state == REXMPP_STREAM_NEGOTIATION) {
    if (rexmpp_xml_match(elem, "http://etherx.jabber.org/streams", "features")) {

      /* Remember features. */
      if (s->stream_features != NULL) {
        rexmpp_xml_free(s->stream_features);
      }
      s->stream_features = rexmpp_xml_clone(elem);

      /* TODO: check for required features properly here. Currently
         assuming that STARTTLS, SASL, and BIND (with an exception for
         SM) are always required if they are present. */
      rexmpp_xml_t *starttls =
        rexmpp_xml_find_child(elem, "urn:ietf:params:xml:ns:xmpp-tls",
                              "starttls");
      rexmpp_xml_t *sasl =
        rexmpp_xml_find_child(elem, "urn:ietf:params:xml:ns:xmpp-sasl",
                              "mechanisms");
      rexmpp_xml_t *bind =
        rexmpp_xml_find_child(elem, "urn:ietf:params:xml:ns:xmpp-bind", "bind");
      rexmpp_xml_t *sm =
        rexmpp_xml_find_child(elem, "urn:xmpp:sm:3", "sm");

      if (starttls != NULL) {
        /* Go for TLS, unless we're both trying to avoid it, and have
           other options. */
        if (! (s->tls_policy == REXMPP_TLS_AVOID &&
               (sasl != NULL || bind != NULL || sm != NULL))) {
          s->stream_state = REXMPP_STREAM_STARTTLS;
          rexmpp_xml_t *starttls_cmd =
            rexmpp_xml_new_elem("starttls", "urn:ietf:params:xml:ns:xmpp-tls");
          rexmpp_send(s, starttls_cmd);
          return REXMPP_SUCCESS;
        }
      } else if (s->tls_policy == REXMPP_TLS_REQUIRE &&
                 s->tls_state != REXMPP_TLS_ACTIVE) {
        /* TLS is required, not established, and there's no such
           feature available; fail here. */
        rexmpp_log(s, LOG_ERR,
                   "TLS is required, but the server doesn't advertise such a feature");
        return REXMPP_E_TLS;
      }

      /* Nothing to negotiate. */
      if (rexmpp_xml_first_elem_child(elem) == NULL) {
        rexmpp_stream_is_ready(s);
        return REXMPP_SUCCESS;
      }

      if (sasl != NULL) {
        s->stream_state = REXMPP_STREAM_SASL;
        s->sasl_state = REXMPP_SASL_NEGOTIATION;
        char mech_list[2048];   /* todo: perhaps grow it dynamically */
        mech_list[0] = '\0';
        rexmpp_xml_t *mechanism;
        for (mechanism = rexmpp_xml_first_elem_child(sasl);
             mechanism != NULL;
             mechanism = rexmpp_xml_next_elem_sibling(mechanism)) {
          if (rexmpp_xml_match(mechanism, "urn:ietf:params:xml:ns:xmpp-sasl",
                               "mechanism")) {
            const char *mech_str = rexmpp_xml_text_child(mechanism);
            snprintf(mech_list + strlen(mech_list),
                     2048 - strlen(mech_list),
                     "%s ",
                     mech_str);
          }
        }
        const char *mech = rexmpp_sasl_suggest_mechanism(s, mech_list);
        if (mech == NULL) {
          rexmpp_log(s, LOG_CRIT, "Failed to decide on a SASL mechanism");
          s->sasl_state = REXMPP_SASL_ERROR;
          return REXMPP_E_SASL;
        }
        rexmpp_log(s, LOG_INFO, "Selected SASL mechanism: %s", mech);
        char *sasl_buf;
        if (rexmpp_sasl_start(s, mech)) {
          s->sasl_state = REXMPP_SASL_ERROR;
          return REXMPP_E_SASL;
        }
        if (rexmpp_sasl_step64(s, "", (char**)&sasl_buf)) {
          s->sasl_state = REXMPP_SASL_ERROR;
          return REXMPP_E_SASL;
        }
        rexmpp_xml_t *auth_cmd =
          rexmpp_xml_new_elem("auth", "urn:ietf:params:xml:ns:xmpp-sasl");
        rexmpp_xml_add_attr(auth_cmd, "mechanism", mech);
        rexmpp_xml_add_text(auth_cmd, sasl_buf);
        free(sasl_buf);
        rexmpp_send(s, auth_cmd);
        return REXMPP_SUCCESS;
      }

      if (s->stream_id != NULL && sm != NULL) {
        s->stream_state = REXMPP_STREAM_SM_RESUME;
        char buf[11];
        snprintf(buf, 11, "%u", s->stanzas_in_count);
        rexmpp_xml_t *sm_resume =
          rexmpp_xml_new_elem("resume", "urn:xmpp:sm:3");
        rexmpp_xml_add_attr(sm_resume, "previd", s->stream_id);
        rexmpp_xml_add_attr(sm_resume, "h", buf);
        rexmpp_send(s, sm_resume);
        return REXMPP_SUCCESS;
      }

      if (bind != NULL) {
        return rexmpp_stream_bind(s);
      }
    } else {
      rexmpp_log(s, LOG_ERR, "Expected stream features, received %s",
                 elem->alt.elem.qname.name);
      return REXMPP_E_STREAM;
    }
  }

  /* IQs. These are the ones that should be processed by the library;
     if a user-facing application wants to handle them on its own, it
     should cancel further processing by the library (so we can send
     errors for unhandled IQs here). */
  if (rexmpp_xml_match(elem, "jabber:client", "iq")) {
    const char *type = rexmpp_xml_find_attr_val(elem, "type");
    /* IQ responses. */
    if (strcmp(type, "result") == 0 || strcmp(type, "error") == 0) {
      const char *id = rexmpp_xml_find_attr_val(elem, "id");
      rexmpp_iq_t *req = s->active_iq, *prev_req = NULL;
      int found = 0;
      while (req != NULL && found == 0) {
        const char *req_id = rexmpp_xml_find_attr_val(req->request, "id");
        const char *req_to = rexmpp_xml_find_attr_val(req->request, "to");
        const char *rep_from = rexmpp_xml_find_attr_val(elem, "from");
        rexmpp_iq_t *req_next = req->next;
        int id_matches = (req_id != NULL) && (strcmp(id, req_id) == 0);
        int jid_matches = 0;
        if (rep_from == NULL) {
          jid_matches = 1;
        } else if (req_to != NULL && rep_from != NULL) {
          jid_matches = (strcmp(req_to, rep_from) == 0);
        }
        if (id_matches && jid_matches) {
          found = 1;
          int success = 0;
          if (strcmp(type, "result") == 0) {
            success = 1;
          }
          /* Remove the callback from the list. */
          if (prev_req == NULL) {
            s->active_iq = req_next;
          } else {
            prev_req->next = req_next;
          }
          /* Finish and free the IQ request structure. */
          rexmpp_iq_finish(s, req, success, elem);
        }
        prev_req = req;
        req = req_next;
      }
    } else if (! rexmpp_jingle_iq(s, elem)) {
      if (strcmp(type, "set") == 0) {
        rexmpp_xml_t *query = rexmpp_xml_first_elem_child(elem);
        int from_server = 0;
        const char *from = rexmpp_xml_find_attr_val(elem, "from");
        if (from == NULL) {
          from_server = 1;
        } else {
          if (strcmp(from, s->initial_jid.domain) == 0) {
            from_server = 1;
          }
        }
        if (from_server &&
            s->manage_roster &&
            rexmpp_xml_match(query, "jabber:iq:roster", "query")) {
          /* Roster push. */
          if (s->roster_ver != NULL) {
            free(s->roster_ver);
          }
          s->roster_ver = NULL;
          const char *roster_ver = rexmpp_xml_find_attr_val(query, "ver");
          if (roster_ver != NULL) {
            s->roster_ver = strdup(roster_ver);
          }
          rexmpp_modify_roster(s, rexmpp_xml_first_elem_child(query));
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
      } else if (strcmp(type, "get") == 0) {
        rexmpp_xml_t *query = rexmpp_xml_first_elem_child(elem);
        if (rexmpp_xml_match(query, "http://jabber.org/protocol/disco#info", "query")) {
          const char *node = rexmpp_xml_find_attr_val(query, "node");
          char *caps_hash = rexmpp_capabilities_hash(s, rexmpp_disco_info(s));
          if (node == NULL ||
              (caps_hash != NULL &&
               s->disco_node != NULL &&
               strlen(node) == strlen(s->disco_node) + 1 + strlen(caps_hash) &&
               strncmp(node, s->disco_node, strlen(s->disco_node)) == 0 &&
               node[strlen(s->disco_node)] == '#' &&
               strcmp(node + strlen(s->disco_node) + 1, caps_hash) == 0)) {
            rexmpp_xml_t *result =
              rexmpp_xml_new_elem("query", "http://jabber.org/protocol/disco#info");
            if (node != NULL) {
              rexmpp_xml_add_attr(result, "node", node);
            }
            rexmpp_xml_add_child(result,
                                 rexmpp_xml_clone_list(rexmpp_disco_info(s)));
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
        } else if (rexmpp_xml_match(query, "urn:xmpp:ping", "ping")) {
          rexmpp_iq_reply(s, elem, "result", NULL);
        } else if (rexmpp_xml_match(query, "jabber:iq:version", "query")) {
          rexmpp_xml_t *reply =
            rexmpp_xml_new_elem("query", "jabber:iq:version");
          rexmpp_xml_t *name = rexmpp_xml_new_elem("name", NULL);
          rexmpp_xml_add_text(name, s->client_name);
          rexmpp_xml_add_child(reply, name);
          rexmpp_xml_t *version = rexmpp_xml_new_elem("version", NULL);
          rexmpp_xml_add_text(version, s->client_version);
          rexmpp_xml_add_child(reply, version);
          rexmpp_iq_reply(s, elem, "result", reply);
        } else {
          /* An unknown request. */
          rexmpp_iq_reply(s, elem, "error",
                          rexmpp_xml_error("cancel", "service-unavailable"));
        }
      }
    }
  }

  /* Incoming presence information. */
  if (rexmpp_xml_match(elem, "jabber:client", "presence") &&
      s->manage_roster &&
      s->track_roster_presence) {
    const char *from = rexmpp_xml_find_attr_val(elem, "from");
    if (from != NULL) {
      struct rexmpp_jid from_jid;
      rexmpp_jid_parse(from, &from_jid);
      if (rexmpp_roster_find_item(s, from_jid.bare, NULL) != NULL) {
        /* The bare JID is in the roster. */
        const char *type = rexmpp_xml_find_attr_val(elem, "type");
        rexmpp_xml_t *cur, *prev;
        if (type == NULL || strcmp(type, "unavailable") == 0) {
          /* Either a new "available" presence or an "unavailable"
             one: remove the previously stored presence for this
             JID. */
          for (prev = NULL, cur = s->roster_presence;
               cur != NULL;
               prev = cur, cur = cur->next) {
            const char *cur_from = rexmpp_xml_find_attr_val(cur, "from");
            if (strcmp(cur_from, from_jid.full) == 0) {
              if (prev == NULL) {
                s->roster_presence = cur->next;
              } else {
                prev->next = cur->next;
              }
              rexmpp_xml_free(cur);
              break;
            }
          }
        }
        if (type == NULL) {
          /* An "available" presence: add it. */
          rexmpp_xml_t *presence = rexmpp_xml_clone(elem);
          presence->next = s->roster_presence;
          s->roster_presence = presence;
        }
      }
    }
  }

  /* Incoming messages. */
  if (rexmpp_xml_match(elem, "jabber:client", "message")) {
    const char *from = rexmpp_xml_find_attr_val(elem, "from");
    if (from != NULL) {
      struct rexmpp_jid from_jid;
      rexmpp_jid_parse(from, &from_jid);
      if (rexmpp_roster_find_item(s, from_jid.bare, NULL) != NULL ||
          strcmp(from_jid.bare, s->assigned_jid.bare) == 0) {
        rexmpp_xml_t *event =
          rexmpp_xml_find_child(elem,
                                "http://jabber.org/protocol/pubsub#event",
                                "event");
        if (event != NULL && s->manage_roster && s->track_roster_events) {
          rexmpp_xml_t *items =
            rexmpp_xml_find_child(event,
                                  "http://jabber.org/protocol/pubsub#event",
                                  "items");
          if (items != NULL) {
            const char *node = rexmpp_xml_find_attr_val(items, "node");
            if (node != NULL) {
              /* Remove the previously stored items for the same sender
                 and node, if any. */
              rexmpp_xml_t *prev, *cur;
              cur = rexmpp_find_event(s, from_jid.bare, node, &prev);
              if (cur) {
                if (prev == NULL) {
                  s->roster_events = cur->next;
                } else {
                  prev->next = cur->next;
                }
                rexmpp_xml_free(cur);
                cur = NULL;
              }

              /* Add the new message. */
              rexmpp_xml_t *message = rexmpp_xml_clone(elem);
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
                rexmpp_xml_t *item;
                for (item = rexmpp_xml_first_elem_child(items);
                     item != NULL;
                     item = rexmpp_xml_next_elem_sibling(item)) {
                  rexmpp_xml_t *conference =
                    rexmpp_xml_find_child(item,
                                          "urn:xmpp:bookmarks:1",
                                          "conference");
                  if (conference == NULL) {
                    continue;
                  }
                  const char *item_id = rexmpp_xml_find_attr_val(item, "id");
                  if (item_id == NULL) {
                    continue;
                  }
                  const char *autojoin = rexmpp_xml_find_attr_val(conference, "autojoin");
                  if (autojoin == NULL) {
                    continue;
                  }
                  if (strcmp(autojoin, "true") == 0 ||
                      strcmp(autojoin, "1") == 0) {
                    rexmpp_xml_t *presence =
                      rexmpp_xml_new_elem("presence", "jabber:client");
                    rexmpp_xml_add_id(presence);
                    rexmpp_xml_add_attr(presence, "from",
                                             s->assigned_jid.full);
                    rexmpp_xml_t *nick =
                      rexmpp_xml_find_child(conference,
                                            "urn:xmpp:bookmarks:1",
                                            "nick");
                    const char *nick_str;
                    if (nick != NULL) {
                      nick_str = rexmpp_xml_text_child(nick);
                    } else {
                      nick_str = s->initial_jid.local;
                    }
                    char *jid = malloc(strlen(item_id) + strlen(nick_str) + 2);
                    sprintf(jid, "%s/%s", item_id, nick_str);
                    rexmpp_xml_add_attr(presence, "to", jid);
                    free(jid);
                    rexmpp_xml_t *x =
                      rexmpp_xml_new_elem("x",
                                          "http://jabber.org/protocol/muc");
                    rexmpp_xml_add_child(presence, x);
                    rexmpp_send(s, presence);
                  }
                }
              }
            }
          }
        }
      }
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
      return rexmpp_process_tls_conn_err(s, rexmpp_tls_connect(s));
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
      const char *challenge = rexmpp_xml_text_child(elem);
      sasl_err = rexmpp_sasl_step64 (s, challenge, (char**)&sasl_buf);
      if (sasl_err) {
        s->sasl_state = REXMPP_SASL_ERROR;
        return REXMPP_E_SASL;
      }
      rexmpp_xml_t *response =
        rexmpp_xml_new_elem("response", "urn:ietf:params:xml:ns:xmpp-sasl");
      rexmpp_xml_add_text(response, sasl_buf);
      free(sasl_buf);
      rexmpp_send(s, response);
    } else if (rexmpp_xml_match(elem, "urn:ietf:params:xml:ns:xmpp-sasl",
                                "success")) {
      const char *success = rexmpp_xml_text_child(elem);
      sasl_err = rexmpp_sasl_step64 (s, success, (char**)&sasl_buf);
      free(sasl_buf);
      if (! sasl_err) {
        rexmpp_log(s, LOG_DEBUG, "SASL success");
      } else {
        s->sasl_state = REXMPP_SASL_ERROR;
        return REXMPP_E_SASL;
      }
      s->sasl_state = REXMPP_SASL_ACTIVE;
      s->xml_parser = rexmpp_xml_parser_reset(s->xml_parser);
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
      const char *resume = rexmpp_xml_find_attr_val(elem, "resume");
      if (resume != NULL) {
        if (s->stream_id != NULL) {
          free(s->stream_id);
        }
        const char *stream_id = rexmpp_xml_find_attr_val(elem, "id");
        s->stream_id = NULL;
        if (stream_id != NULL) {
          s->stream_id = strdup(stream_id);
        }
      }
      rexmpp_stream_is_ready(s);
    } else if (rexmpp_xml_match(elem, "urn:xmpp:sm:3", "failed")) {
      s->stream_state = REXMPP_STREAM_SM_ACKS;
      s->sm_state = REXMPP_SM_NEGOTIATION;
      rexmpp_xml_t *sm_enable =
        rexmpp_xml_new_elem("enable", "urn:xmpp:sm:3");
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
      rexmpp_xml_t *sm_enable =
        rexmpp_xml_new_elem("enable", "urn:xmpp:sm:3");
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
        rexmpp_iq_t *iq = s->active_iq;
        s->active_iq = next;
        rexmpp_iq_finish(s, iq, 0, NULL);
      }
      rexmpp_xml_t *child =
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


/* These SAX handlers are similar to those in rexmpp_xml.c, might be
   nice to reuse them. */
void rexmpp_sax_characters (rexmpp_t *s, const char *ch, size_t len)
{
  if (s->current_element != NULL) {
    rexmpp_xml_t *last_node = s->current_element->alt.elem.children;
    if (last_node != NULL && last_node->type == REXMPP_XML_TEXT) {
      /* The last child is textual as well, just extend it */
      size_t last_len = strlen(last_node->alt.text);
      last_node->alt.text = realloc(last_node->alt.text, last_len + len + 1);
      strncpy(last_node->alt.text + last_len, ch, len);
      last_node->alt.text[last_len + len] = '\0';
    } else {
      rexmpp_xml_t *text_node = rexmpp_xml_new_text_len(ch, len);
      if (text_node != NULL) {
        text_node->next = s->current_element->alt.elem.children;
        s->current_element->alt.elem.children = text_node;
      }
    }
  }
}

void rexmpp_sax_start_elem_ns (rexmpp_t *s,
                               const char *name,
                               const char *namespace,
                               rexmpp_xml_attr_t *attributes)
{
  if (s->stream_state == REXMPP_STREAM_OPENING &&
      s->current_element == NULL &&
      strcmp(name, "stream") == 0 &&
      strcmp(namespace, "http://etherx.jabber.org/streams") == 0) {
    rexmpp_log(s, LOG_DEBUG, "stream start");
    s->stream_state = REXMPP_STREAM_NEGOTIATION;
    rexmpp_xml_attribute_free_list(attributes);
    return;
  }

  if (s->stream_state != REXMPP_STREAM_OPENING) {
    if (s->current_element == NULL) {
      s->current_element = rexmpp_xml_new_elem(name, namespace);
      s->current_element_root = s->current_element;
    } else {
      rexmpp_xml_t *node = rexmpp_xml_new_elem(name, namespace);
      node->next = s->current_element->alt.elem.children;
      s->current_element->alt.elem.children = node;
      s->current_element = node;
    }
    s->current_element->alt.elem.attributes = attributes;
  }
}

void rexmpp_sax_end_elem_ns (rexmpp_t *s)
{
  if ((s->stream_state == REXMPP_STREAM_CLOSING ||
       s->stream_state == REXMPP_STREAM_ERROR) &&
      s->current_element == NULL) {
    rexmpp_log(s, LOG_DEBUG, "stream end");
    if (s->sasl_state == REXMPP_SASL_ACTIVE) {
      rexmpp_sasl_ctx_cleanup(s);
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
    /* Find the parent, set it as current element. */
    rexmpp_xml_t *parent = s->current_element_root;
    while (parent->alt.elem.children != s->current_element) {
      parent = parent->alt.elem.children;
    }
    s->current_element = parent;
  } else {
    /* Done parsing this element; reverse all the lists of children
       and queue it. */
    rexmpp_xml_reverse_children(s->current_element);
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
    rexmpp_xml_t *presence =
      rexmpp_xml_new_elem("presence", "jabber:client");
    rexmpp_xml_add_id(presence);
    rexmpp_xml_add_attr(presence, "type", "unavailable");
    rexmpp_send(s, presence);
  }

  s->stream_state = REXMPP_STREAM_CLOSE_REQUESTED;

  if (s->sm_state == REXMPP_SM_ACTIVE) {
    int ret = rexmpp_sm_ack(s);
    if (ret > REXMPP_E_AGAIN) {
      return ret;
    }
  }
  if (s->send_buffer == NULL) {
    return rexmpp_close(s);
  } else {
    return REXMPP_E_AGAIN;
  }
}

rexmpp_err_t rexmpp_run (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    rexmpp_log(s, LOG_ERR, "Failed to get time: %s", strerror(errno));
    return REXMPP_E_OTHER;
  }

#ifdef HAVE_CURL
  /* curl may work independently from everything else. */
  int curl_running_handles;
  CURLMcode curl_code;
  do {
    curl_code = curl_multi_perform(s->curl_multi, &curl_running_handles);
  } while (curl_code == CURLM_CALL_MULTI_PERFORM);
  CURLMsg *cmsg;
  int curl_queue;
  do {
    cmsg = curl_multi_info_read(s->curl_multi, &curl_queue);
    if (cmsg != NULL && cmsg->msg == CURLMSG_DONE) {
      CURL *e = cmsg->easy_handle;
      struct rexmpp_http_upload_task *task;
      curl_easy_getinfo(e, CURLINFO_PRIVATE, &task);
      rexmpp_log(s, LOG_DEBUG, "%s upload is finished", task->fname);
      rexmpp_upload_task_finish(task);
      curl_multi_remove_handle(s->curl_multi, e);
      curl_easy_cleanup(e);
    }
  } while (cmsg != NULL);
#endif

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
      s->resolver_state = REXMPP_RESOLVER_SRV;
      snprintf(srv_query, srv_query_buf_len,
               "_xmpps-client._tcp.%s.", s->initial_jid.domain);
      rexmpp_dns_resolve(s, srv_query, 33, 1,
                         "xmpps", rexmpp_srv_cb);
      snprintf(srv_query, srv_query_buf_len,
               "_xmpp-client._tcp.%s.", s->initial_jid.domain);
      rexmpp_dns_resolve(s, srv_query, 33, 1,
                         "xmpp", rexmpp_srv_cb);
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

  /* Don't try to reconnect if a stream is requested to be closed. */
  if (s->tcp_state == REXMPP_TCP_ERROR &&
      (s->stream_state == REXMPP_STREAM_CLOSE_REQUESTED ||
       s->stream_state == REXMPP_STREAM_CLOSING)) {
    return REXMPP_E_TCP;
  }

  /* Resolving SRV records. This continues in rexmpp_srv_tls_cb,
     rexmpp_srv_cb. */
  if (rexmpp_dns_process(s, read_fds, write_fds)) {
    return REXMPP_E_DNS;
  }

  /* Initiating a connection after SRV resolution. */
  if (s->resolver_state == REXMPP_RESOLVER_READY) {
    s->resolver_state = REXMPP_RESOLVER_NONE;
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

  /* Connecting. Continues in rexmpp_process_conn_err, possibly
     leading to stream opening. */
  if (s->tcp_state == REXMPP_TCP_CONNECTING) {
    rexmpp_err_t err =
      rexmpp_process_conn_err(s,
                              rexmpp_tcp_conn_proceed(s, &s->server_connection,
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

  /* Jingle activity. */
  rexmpp_jingle_run(s, read_fds, write_fds);

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
      s->last_network_activity.tv_sec + s->ping_delay <= now.tv_sec) {
    if (s->ping_requested == 0) {
      s->ping_requested = 1;
      rexmpp_xml_t *ping_cmd =
        rexmpp_xml_new_elem("ping", "urn:xmpp:ping");
      rexmpp_iq_new(s, "get", s->initial_jid.domain,
                    ping_cmd, rexmpp_pong, NULL);
    } else {
      rexmpp_log(s, LOG_WARNING, "Ping timeout, reconnecting.");
      rexmpp_cleanup(s);
      rexmpp_schedule_reconnect(s);
      return REXMPP_E_AGAIN;
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
    rexmpp_err_t err = rexmpp_process_tls_conn_err(s, rexmpp_tls_connect(s));
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
    rexmpp_tls_err_t err = rexmpp_tls_disconnect(s, s->tls);
    if (err == REXMPP_TLS_SUCCESS) {
      rexmpp_log(s, LOG_DEBUG, "TLS disconnected");
      s->tls_state = REXMPP_TLS_INACTIVE;
      rexmpp_cleanup(s);
      s->tcp_state = REXMPP_TCP_CLOSED;
    } else if (err != REXMPP_TLS_E_AGAIN) {
      s->tls_state = REXMPP_TLS_ERROR;
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

int rexmpp_fds (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds) {
  int conn_fd, tls_fd, jingle_fd, max_fd = 0;

  max_fd = rexmpp_dns_fds(s, read_fds, write_fds);

  jingle_fd = rexmpp_jingle_fds(s, read_fds, write_fds);
  if (jingle_fd > max_fd) {
    max_fd = jingle_fd;
  }

#ifdef HAVE_CURL
  int curl_fd;
  curl_multi_fdset(s->curl_multi, read_fds, write_fds, NULL, &curl_fd);
  if (curl_fd >= max_fd) {
    max_fd = curl_fd + 1;
  }
#endif

  if (s->tcp_state == REXMPP_TCP_CONNECTING) {
    conn_fd = rexmpp_tcp_conn_fds(s, &s->server_connection, read_fds, write_fds);
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
    tls_fd = rexmpp_tls_fds(s, read_fds, write_fds);
    if (tls_fd > max_fd) {
      max_fd = tls_fd;
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

struct timespec *rexmpp_timeout (rexmpp_t *s,
                                 struct timespec *max_tv,
                                 struct timespec *tv)
{
  struct timespec *ret = max_tv;

  if (s->resolver_state != REXMPP_RESOLVER_NONE &&
      s->resolver_state != REXMPP_RESOLVER_READY) {

  } else if (s->tcp_state == REXMPP_TCP_CONNECTING) {
    ret = rexmpp_tcp_conn_timeout(s, &s->server_connection, max_tv, tv);
  }

  ret = rexmpp_jingle_timeout(s, ret, tv);

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  if (s->reconnect_number > 0 &&
      s->next_reconnect_time.tv_sec > now.tv_sec &&
      (ret == NULL ||
       s->next_reconnect_time.tv_sec - now.tv_sec < ret->tv_sec)) {
    tv->tv_sec = s->next_reconnect_time.tv_sec - now.tv_sec;
    tv->tv_nsec = 0;
    ret = tv;
  }

  if (s->tcp_state == REXMPP_TCP_CONNECTED &&
      s->last_network_activity.tv_sec + s->ping_delay > now.tv_sec) {
    time_t next_ping =
      s->last_network_activity.tv_sec + s->ping_delay - now.tv_sec;
    if (ret == NULL || next_ping < ret->tv_sec) {
      tv->tv_sec = next_ping;
      tv->tv_nsec = 0;
      ret = tv;
    }
  }

#ifdef HAVE_CURL
  long curl_timeout;            /* in milliseconds */
  curl_multi_timeout(s->curl_multi, &curl_timeout);
  if (curl_timeout >= 0 &&
      (curl_timeout / 1000 < ret->tv_sec ||
       (curl_timeout / 1000 == ret->tv_sec &&
        (curl_timeout % 1000) * 1000000 < ret->tv_nsec))) {
    tv->tv_sec = curl_timeout / 1000;
    tv->tv_nsec = (curl_timeout % 1000) * 1000000;
    ret = tv;
  }
#endif

  return ret;
}
