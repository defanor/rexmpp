/**
   @file rexmpp_console.c
   @brief A console module
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.

   The "console" is supposed to provide a few common and basic
   commands, and to be easily embeddable into programs, similarly to
   an XML console.
*/

#include <string.h>

#include "rexmpp.h"
#include "rexmpp_xml.h"
#include "rexmpp_openpgp.h"
#include "rexmpp_http_upload.h"
#include "rexmpp_jingle.h"
#include "rexmpp_pubsub.h"
#include "rexmpp_console.h"


void rexmpp_console_printf (rexmpp_t *s, const char *format, ...)
{
  va_list args;
  if (s->console_print_cb != NULL) {
    va_start(args, format);
    s->console_print_cb (s, format, args);
    va_end(args);
  }
}

const char *rexmpp_console_message_string (rexmpp_t *s, rexmpp_xml_t *node) {
  const char *ret = NULL;
  rexmpp_xml_t *openpgp =
    rexmpp_xml_find_child(node, "urn:xmpp:openpgp:0", "openpgp");
  if (openpgp != NULL) {
    int valid;
    rexmpp_xml_t *elem = rexmpp_openpgp_decrypt_verify_message(s, node, &valid);
    if (! valid) {
      rexmpp_console_printf(s, "An invalid OpenPGP message!\n");
    }

    if (elem != NULL) {
      rexmpp_xml_t *payload =
        rexmpp_xml_find_child(elem, "urn:xmpp:openpgp:0", "payload");
      if (payload != NULL) {
        rexmpp_xml_t *pl_body =
          rexmpp_xml_find_child(payload, "jabber:client", "body");
        if (pl_body != NULL) {
          ret = rexmpp_xml_text_child(pl_body);
        }
      }
      rexmpp_xml_free(elem);
    }
  }
  if (ret == NULL) {
    rexmpp_xml_t *body =
      rexmpp_xml_find_child(node, "jabber:client", "body");
    ret = rexmpp_xml_text_child(body);
  }
  return ret;
}

void rexmpp_console_on_send (rexmpp_t *s, rexmpp_xml_t *node) {
  if (rexmpp_xml_match(node, "jabber:client", "message")) {
    const char *to = rexmpp_xml_find_attr_val(node, "to");
    if (to != NULL) {
      /* "from" should be set for verification. */
      int added_from = 0;
      if (rexmpp_xml_find_attr_val(node, "from") == NULL) {
        rexmpp_xml_add_attr(node, "from", to);
        added_from = 1;
      }
      const char *str = rexmpp_console_message_string(s, node);
      if (added_from) {
        rexmpp_xml_remove_attr(node, "from");
      }
      if (str != NULL) {
        rexmpp_console_printf(s, "You tell %s: %s\n", to, str);
      }
    }
  }
  if (rexmpp_xml_match(node, "jabber:client", "presence")) {
    const char *presence_type = rexmpp_xml_find_attr_val(node, "type");
    const char *presence_to = rexmpp_xml_find_attr_val(node, "to");
    if (presence_to == NULL) {
      rexmpp_console_printf(s, "Becoming %s\n",
                            (presence_type == NULL) ?
                            "available" :
                            presence_type);
    } else {
      if (presence_type != NULL && ! strcmp(presence_type, "subscribe")) {
        rexmpp_console_printf(s,
                              "Requesting a subscription to %s's presence.\n",
                              presence_to);
      }
      if (presence_type != NULL && ! strcmp(presence_type, "subscribed")) {
        rexmpp_console_printf(s,
                              "Approving %s's presence subscription request.\n",
                              presence_to);
      }
      if (presence_type != NULL && ! strcmp(presence_type, "unsubscribed")) {
        rexmpp_console_printf(s,
                              "Denying %s's presence subscription request.\n",
                              presence_to);
      }
    }
  }
}

void rexmpp_console_on_recv (rexmpp_t *s, rexmpp_xml_t *node) {
  if (rexmpp_xml_match(node, "jabber:client", "message")) {
    rexmpp_xml_t *sent = rexmpp_xml_find_child(node, "urn:xmpp:carbons:2", "sent");
    if (sent != NULL) {
      rexmpp_xml_t *fwd =
        rexmpp_xml_find_child(sent, "urn:xmpp:forward:0", "forwarded");
      if (fwd != NULL) {
        rexmpp_xml_t *msg =
          rexmpp_xml_find_child(fwd, "jabber:client", "message");
        if (msg != NULL) {
          const char *to = rexmpp_xml_find_attr_val(msg, "to");
          const char *str = rexmpp_console_message_string(s, msg);
          if (str != NULL) {
            rexmpp_console_printf(s, "You tell %s: %s\n", to, str);
          }
        }
      }
    }

    rexmpp_xml_t *received =
      rexmpp_xml_find_child(node, "urn:xmpp:carbons:2", "received");
    if (received != NULL) {
      rexmpp_xml_t *fwd =
        rexmpp_xml_find_child(received, "urn:xmpp:forward:0", "forwarded");
      if (fwd != NULL) {
        rexmpp_xml_t *msg =
          rexmpp_xml_find_child(fwd, "jabber:client", "message");
        if (msg != NULL) {
          const char *from = rexmpp_xml_find_attr_val(msg, "from");
          const char *str = rexmpp_console_message_string(s, msg);
          if (str != NULL) {
            rexmpp_console_printf(s, "%s tells you: %s\n", from, str);
          }
        }
      }
    }

    const char *from = rexmpp_xml_find_attr_val(node, "from");
    if (from != NULL) {
      const char *str = rexmpp_console_message_string(s, node);
      if (str != NULL) {
        rexmpp_console_printf(s, "%s tells you: %s\n", from, str);
      }
    }
  }
  if (rexmpp_xml_match(node, "jabber:client", "presence")) {
    const char *presence_type = rexmpp_xml_find_attr_val(node, "type");
    const char *from = rexmpp_xml_find_attr_val(node, "from");
    if (presence_type != NULL && ! strcmp(presence_type, "subscribe")) {
      rexmpp_console_printf(s, "%s requests a presence subscription\n", from);
    } else if (presence_type != NULL && ! strcmp(presence_type, "subscribed")) {
      rexmpp_console_printf(s, "%s approves a presence subscription\n", from);
    } else if (presence_type != NULL && ! strcmp(presence_type, "unsubscribed")) {
      rexmpp_console_printf(s, "%s denies a presence subscription\n", from);
    } else {
      rexmpp_console_printf(s, "%s is %s", from,
                            (presence_type == NULL) ?
                            "available" :
                            presence_type);
      rexmpp_xml_t *show =
        rexmpp_xml_find_child(node, "jabber:client", "show");
      if (show != NULL) {
        rexmpp_console_printf(s, " (%s)",
                              rexmpp_xml_text_child(show));
      }
      rexmpp_xml_t *status =
        rexmpp_xml_find_child(node, "jabber:client", "status");
      if (status != NULL) {
        rexmpp_console_printf(s, ": %s",
                              rexmpp_xml_text_child(status));
      }
      rexmpp_console_printf(s, "\n");
    }
  }
}


void rexmpp_console_roster_deleted (rexmpp_t *s,
                                    void *ptr,
                                    rexmpp_xml_t *req,
                                    rexmpp_xml_t *response,
                                    int success)
{
  (void)ptr;
  (void)response;
  rexmpp_xml_t *item =
    rexmpp_xml_find_child(rexmpp_xml_find_child(req,
                                                "jabber:iq:roster",
                                                "query"),
                          "jabber:iq:roster", "item");
  const char *jid = rexmpp_xml_find_attr_val(item, "jid");
  if (success) {
    rexmpp_console_printf(s, "Deleted %s from the roster.\n", jid);
  } else {
    rexmpp_console_printf(s, "Failed to delete %s from the roster.\n", jid);
  }
}

void rexmpp_console_roster_added (rexmpp_t *s,
                                  void *ptr,
                                  rexmpp_xml_t *req,
                                  rexmpp_xml_t *response,
                                  int success)
{
  (void)ptr;
  (void)response;
  rexmpp_xml_t *item =
    rexmpp_xml_find_child(rexmpp_xml_find_child(req,
                                                "jabber:iq:roster",
                                                "query"),
                          "jabber:iq:roster", "item");
  const char *jid = rexmpp_xml_find_attr_val(item, "jid");
  if (success) {
    rexmpp_console_printf(s, "Added %s into the roster.\n", jid);
  } else {
    rexmpp_console_printf(s, "Failed to add %s into the roster.\n", jid);
  }
}

void rexmpp_console_on_run (rexmpp_t *s, rexmpp_err_t result) {
  if (result == REXMPP_SUCCESS) {
    rexmpp_console_printf(s, "Done.\n");
    return;
  }
}

void rexmpp_console_on_upload (rexmpp_t *s, void *cb_data, const char *url) {
  char *fpath = cb_data;
  if (url == NULL) {
    rexmpp_console_printf(s, "Failed to upload %s.\n", fpath);
  } else {
    rexmpp_console_printf(s, "Uploaded %s to <%s>.\n", fpath, url);
  }
  free(fpath);
}

void rexmpp_console_disco_info (rexmpp_t *s,
                                void *ptr,
                                rexmpp_xml_t *req,
                                rexmpp_xml_t *response,
                                int success)
{
  (void)ptr;
  (void)req;
  if (! success) {
    rexmpp_console_printf(s, "Failed to discover info.\n");
    return;
  }
  rexmpp_xml_t *query =
    rexmpp_xml_find_child(response, "http://jabber.org/protocol/disco#info",
                          "query");
  if (query == NULL) {
    rexmpp_console_printf(s, "No disco#info query in response.\n");
    return;
  }
  const char *from = rexmpp_xml_find_attr_val(response, "from");
  if (from == NULL) {
    rexmpp_console_printf(s, "No 'from' property in response.\n");
    return;
  }
  rexmpp_console_printf(s, "Discovered info for %s:\n", from);
  rexmpp_xml_t *child = rexmpp_xml_first_elem_child(query);
  while (child != NULL) {
    if (rexmpp_xml_match(child, "http://jabber.org/protocol/disco#info",
                         "feature")) {
      const char *var = rexmpp_xml_find_attr_val(child, "var");
      rexmpp_console_printf(s, "- feature var %s\n", var);
    } else if (rexmpp_xml_match(child, "http://jabber.org/protocol/disco#info",
                                "identity")) {
      const char *category = rexmpp_xml_find_attr_val(child, "category");
      const char *type = rexmpp_xml_find_attr_val(child, "type");
      const char *name = rexmpp_xml_find_attr_val(child, "name");
      rexmpp_console_printf(s, "- identity name %s, type %s, category %s\n",
                            name, type, category);
    } else {
      rexmpp_console_printf(s, "Encountered an unknown disco#info element.\n");
    }
    child = rexmpp_xml_next_elem_sibling(child);
  }
  rexmpp_console_printf(s, "(end of discovered info for %s)\n", from);
}

void rexmpp_console_disco_items (rexmpp_t *s,
                                 void *ptr,
                                 rexmpp_xml_t *req,
                                 rexmpp_xml_t *response,
                                 int success)
{
  (void)ptr;
  (void)req;
  if (! success) {
    rexmpp_console_printf(s, "Failed to discover items.\n");
    return;
  }
  rexmpp_xml_t *query =
    rexmpp_xml_find_child(response, "http://jabber.org/protocol/disco#items",
                          "query");
  if (query == NULL) {
    rexmpp_console_printf(s, "No disco#items query in response.\n");
    return;
  }
  const char *from = rexmpp_xml_find_attr_val(response, "from");
  if (from == NULL) {
    rexmpp_console_printf(s, "No 'from' property in response.\n");
    return;
  }
  rexmpp_console_printf(s, "Discovered items for %s:\n", from);
  rexmpp_xml_t *child = rexmpp_xml_first_elem_child(query);
  while (child != NULL) {
    if (rexmpp_xml_match(child, "http://jabber.org/protocol/disco#items",
                         "item")) {
      const char *jid = rexmpp_xml_find_attr_val(child, "jid");
      const char *name = rexmpp_xml_find_attr_val(child, "name");
      const char *node = rexmpp_xml_find_attr_val(child, "node");
      rexmpp_console_printf(s, "- item jid %s, name %s, node %s\n", jid, name, node);
    } else {
      rexmpp_console_printf(s, "Encountered an unknown disco#items element.\n");
    }
    child = rexmpp_xml_next_elem_sibling(child);
  }
  rexmpp_console_printf(s, "(end of discovered items for %s)\n", from);
}

void rexmpp_console_pubsub_node_deleted (rexmpp_t *s,
                                         void *ptr,
                                         rexmpp_xml_t *req,
                                         rexmpp_xml_t *response,
                                         int success)
{
  (void)ptr;
  (void)req;
  (void)response;
  if (success) {
    rexmpp_console_printf(s, "Deleted the pubsub node.\n");
  } else {
    rexmpp_console_printf(s, "Failed to delete the pubsub node.\n");
  }
}

void rexmpp_console_blocklist (rexmpp_t *s,
                               void *ptr,
                               rexmpp_xml_t *req,
                               rexmpp_xml_t *response,
                               int success)
{
  (void)ptr;
  (void)req;
  if (success) {
    rexmpp_xml_t *bl =
      rexmpp_xml_find_child(response, "urn:xmpp:blocking", "blocklist");
    if (bl == NULL) {
      rexmpp_console_printf(s, "No blocklist element in the response.\n");
      return;
    }
    rexmpp_console_printf(s, "Block list:");
    rexmpp_xml_t *child = rexmpp_xml_first_elem_child(bl);
    while (child != NULL) {
      if (rexmpp_xml_match(child, "urn:xmpp:blocking", "item")) {
        const char *jid = rexmpp_xml_find_attr_val(child, "jid");
        rexmpp_console_printf(s, " %s", jid);
      } else {
        rexmpp_console_printf(s, "Encountered an unknown blocklist child element.\n");
      }
      child = rexmpp_xml_next_elem_sibling(child);
    }
    rexmpp_console_printf(s, "\n");
  } else {
    rexmpp_console_printf(s, "Failed to retrieve block list.\n");
  }
}

void rexmpp_console_blocklist_blocked (rexmpp_t *s,
                                       void *ptr,
                                       rexmpp_xml_t *req,
                                       rexmpp_xml_t *response,
                                       int success)
{
  (void)ptr;
  (void)req;
  (void)response;
  if (success) {
    rexmpp_console_printf(s, "Blocklisted successfully.\n");
  } else {
    rexmpp_console_printf(s, "Failed to blocklist.\n");
  }
}

void rexmpp_console_blocklist_unblocked (rexmpp_t *s,
                                         void *ptr,
                                         rexmpp_xml_t *req,
                                         rexmpp_xml_t *response,
                                         int success)
{
  (void)ptr;
  (void)req;
  (void)response;
  if (success) {
    rexmpp_console_printf(s, "Un-blocklisted successfully.\n");
  } else {
    rexmpp_console_printf(s, "Failed to un-blocklist.\n");
  }
}

void rexmpp_console_feed (rexmpp_t *s, char *str, ssize_t str_len) {
  /* todo: buffering */
  (void)str_len;                /* Unused for now (todo). */
  char *words_save_ptr;
  rexmpp_xml_t *presence;
  char *word, *jid_str, *msg_text;
  struct rexmpp_jid jid;
  word = strtok_r(str, " ", &words_save_ptr);
  if (word == NULL) {
    return;
  }

  const char *help =
    "Available commands:\n"
    "help\n"
    "quit\n"
    "tell <jid> <message>\n"
    "signcrypt <jid> <message>\n"
    "sign <jid> <message>\n"
    "crypt <jid> <message>\n"
    "key publish <fingerprint>\n"
    "key retract <fingerprint>\n"
    "muc join <conference> [as] <nick>\n"
    "muc leave <conference> [as] <nick>\n"
    "muc tell <conference> <message>\n"
    "roster list\n"
    "roster add <jid>\n"
    "roster delete <jid>\n"
    "subscription request <jid>\n"
    "subscription approve <jid>\n"
    "subscription deny <jid>\n"
    "http-upload <file path>\n"
    "jingle terminate <sid>\n"
    "jingle decline <sid>\n"
    "jingle accept-file <sid> <file path>\n"
    "jingle send-file <jid> <file path>\n"
    "jingle accept-call <sid> <in port> <out port>\n"
    "jingle call <jid> <in port> <out port>\n"
    "disco info <jid>\n"
    "disco items <jid>\n"
    "pubsub node delete <service_jid> <node>\n"
    "blocklist\n"
    "blocklist block <jid>\n"
    "blocklist unblock <jid>\n"
    ;

  if (! strcmp(word, "help")) {
    rexmpp_console_printf(s, help);
  }

  if (! strcmp(word, "quit")) {
    rexmpp_console_printf(s, "Quitting.\n");
    rexmpp_stop(s);
    return;
  }

  if (! strcmp(word, "key")) {
    word = strtok_r(NULL, " ", &words_save_ptr);
    if (! strcmp(word, "publish")) {
      char *fingerprint = strtok_r(NULL, " ", &words_save_ptr);
      rexmpp_openpgp_publish_key(s, fingerprint);
    }
    if (! strcmp(word, "retract")) {
      char *fingerprint = strtok_r(NULL, " ", &words_save_ptr);
      rexmpp_openpgp_retract_key(s, fingerprint);
    }
  }

  if (! strcmp(word, "tell")) {
    jid_str = strtok_r(NULL, " ", &words_save_ptr);
    if (jid_str == NULL || rexmpp_jid_parse(jid_str, &jid)) {
      return;
    }
    msg_text = jid_str + strlen(jid_str) + 1;

    rexmpp_xml_t *msg = rexmpp_xml_new_elem("message", "jabber:client");
    rexmpp_xml_add_id(s, msg);
    rexmpp_xml_add_attr(msg, "to", jid.full);
    rexmpp_xml_add_attr(msg, "type", "chat");
    rexmpp_xml_t *body = rexmpp_xml_new_elem("body", NULL);
    rexmpp_xml_add_text(body, msg_text);
    rexmpp_xml_add_child(msg, body);
    rexmpp_send(s, msg);
  }

  if ((strcmp(word, "signcrypt") == 0) ||
      (strcmp(word, "sign") == 0) ||
      (strcmp(word, "crypt") == 0)) {
    jid_str = strtok_r(NULL, " ", &words_save_ptr);
    if (jid_str == NULL || rexmpp_jid_parse(jid_str, &jid)) {
      return;
    }
    msg_text = jid_str + strlen(jid_str) + 1;
    rexmpp_xml_t *body =
      rexmpp_xml_new_elem("body", "jabber:client");
    rexmpp_xml_add_text(body, msg_text);
    const char *rcpt[2];
    rcpt[0] = jid.full;
    rcpt[1] = NULL;
    char *b64 = NULL;
    if (strcmp(word, "signcrypt") == 0) {
      b64 = rexmpp_openpgp_payload(s, body, rcpt, NULL, REXMPP_OX_SIGNCRYPT);
    } else if (strcmp(word, "sign") == 0) {
      b64 = rexmpp_openpgp_payload(s, body, rcpt, NULL, REXMPP_OX_SIGN);
    } else if (strcmp(word, "crypt") == 0) {
      b64 = rexmpp_openpgp_payload(s, body, rcpt, NULL, REXMPP_OX_CRYPT);
    }
    rexmpp_xml_t *openpgp =
      rexmpp_xml_new_elem("openpgp", "urn:xmpp:openpgp:0");
    rexmpp_xml_add_text(openpgp, b64);
    free(b64);

    rexmpp_xml_t *msg = rexmpp_xml_new_elem("message", "jabber:client");
    rexmpp_xml_add_id(s, msg);
    rexmpp_xml_add_attr(msg, "to", jid.full);
    rexmpp_xml_add_attr(msg, "type", "chat");
    rexmpp_xml_add_child(msg, openpgp);

    body = rexmpp_xml_new_elem("body", "jabber:client");
    rexmpp_xml_add_text(body, "This is a secret message.");
    rexmpp_xml_add_child(msg, body);

    rexmpp_send(s, msg);
  }

  if (! strcmp(word, "muc")) {
    word = strtok_r(NULL, " ", &words_save_ptr);
    if (! strcmp(word, "tell")) {
      jid_str = strtok_r(NULL, " ", &words_save_ptr);
      if (jid_str == NULL || rexmpp_jid_parse(jid_str, &jid)) {
        return;
      }
      msg_text = jid_str + strlen(jid_str) + 1;

      rexmpp_xml_t *msg = rexmpp_xml_new_elem("message", "jabber:client");
      rexmpp_xml_add_id(s, msg);
      rexmpp_xml_add_attr(msg, "to", jid.full);
      rexmpp_xml_add_attr(msg, "type", "groupchat");
      rexmpp_xml_t *body = rexmpp_xml_new_elem("body", NULL);
      rexmpp_xml_add_text(body, msg_text);
      rexmpp_xml_add_child(msg, body);
      rexmpp_send(s, msg);
    }
    if (! strcmp(word, "join")) {
      jid_str = strtok_r(NULL, " ", &words_save_ptr);
      if (jid_str == NULL || rexmpp_jid_parse(jid_str, &jid)) {
        return;
      }
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (! strcmp(word, "as")) {
        word = strtok_r(NULL, " ", &words_save_ptr);
      }
      if (word == NULL) {
        return;
      }
      char *full_jid = malloc(strlen(jid.bare) + strlen(word) + 2);
      snprintf(full_jid, strlen(jid_str) + strlen(word) + 2, "%s/%s",
               jid.bare, word);
      presence = rexmpp_xml_new_elem("presence", "jabber:client");
      rexmpp_xml_add_id(s, presence);
      rexmpp_xml_add_attr(presence, "from", s->assigned_jid.full);
      rexmpp_xml_add_attr(presence, "to", full_jid);
      rexmpp_xml_t *x =
        rexmpp_xml_new_elem("x", "http://jabber.org/protocol/muc");
      rexmpp_xml_add_child(presence, x);
      rexmpp_send(s, presence);
      free(full_jid);
    }
    if (! strcmp(word, "leave")) {
      jid_str = strtok_r(NULL, " ", &words_save_ptr);
      if (jid_str == NULL || rexmpp_jid_parse(jid_str, &jid)) {
        return;
      }
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (! strcmp(word, "as")) {
        word = strtok_r(NULL, " ", &words_save_ptr);
      }
      if (word == NULL) {
        return;
      }
      char *full_jid = malloc(strlen(jid.bare) + strlen(word) + 2);
      snprintf(full_jid, strlen(jid_str) + strlen(word) + 2, "%s/%s",
               jid.bare, word);
      presence = rexmpp_xml_new_elem("presence", "jabber:client");
      rexmpp_xml_add_id(s, presence);
      rexmpp_xml_add_attr(presence, "from", s->assigned_jid.full);
      rexmpp_xml_add_attr(presence, "to", full_jid);
      rexmpp_xml_add_attr(presence, "type", "unavailable");
      rexmpp_send(s, presence);
      free(full_jid);
    }
  }

  if (! strcmp(word, "roster")) {
    word = strtok_r(NULL, " ", &words_save_ptr);
    if (word == NULL) {
      return;
    }
    if (! strcmp(word, "list")) {
      rexmpp_xml_t *item;
      for (item = s->roster_items;
           item != NULL;
           item = item->next) {
        const char *item_jid = rexmpp_xml_find_attr_val(item, "jid");
        const char *item_ask = rexmpp_xml_find_attr_val(item, "ask");
        const char *item_subscription =
          rexmpp_xml_find_attr_val(item, "subscription");
        char *item_presence = "unavailable";
        if (s->track_roster_presence) {
          for (presence = s->roster_presence;
               presence != NULL;
               presence = presence->next) {
            const char *presence_from =
              rexmpp_xml_find_attr_val(presence, "from");
            if (presence_from != NULL) {
              rexmpp_jid_parse(presence_from, &jid);
              if (! strcmp(jid.bare, item_jid)) {
                item_presence = "available";
              }
            }
          }
        }
        rexmpp_console_printf(s,
                              "%s: subscription = %s, ask = %s, "
                              "presence = %s\n",
                              item_jid, item_subscription, item_ask,
                              item_presence);
      }
    } else if (! strcmp(word, "delete")) {
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (word == NULL) {
        return;
      }
      rexmpp_xml_t *delete_item =
        rexmpp_xml_new_elem("item", "jabber:iq:roster");
      rexmpp_xml_add_attr(delete_item, "jid", word);
      rexmpp_xml_add_attr(delete_item, "subscription", "remove");
      rexmpp_xml_t *delete_query =
        rexmpp_xml_new_elem("query", "jabber:iq:roster");
      rexmpp_xml_add_child(delete_query, delete_item);
      rexmpp_iq_new(s, "set", NULL, delete_query,
                    rexmpp_console_roster_deleted, NULL);
    } else if (! strcmp(word, "add")) {
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (word == NULL) {
        return;
      }
      rexmpp_xml_t *add_item =
        rexmpp_xml_new_elem("item", "jabber:iq:roster");
      rexmpp_xml_add_attr(add_item, "jid", word);
      rexmpp_xml_t *add_query =
        rexmpp_xml_new_elem("query", "jabber:iq:roster");
      rexmpp_xml_add_child(add_query, add_item);
      rexmpp_iq_new(s, "set", NULL, add_query,
                    rexmpp_console_roster_added, NULL);
    }
  }

  if (! strcmp(word, "subscription")) {
    word = strtok_r(NULL, " ", &words_save_ptr);
    if (word == NULL) {
      return;
    }
    if (! strcmp(word, "request")) {
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (word == NULL) {
        return;
      }
      presence = rexmpp_xml_new_elem("presence", "jabber:client");
      rexmpp_xml_add_id(s, presence);
      rexmpp_xml_add_attr(presence, "to",  word);
      rexmpp_xml_add_attr(presence, "type", "subscribe");
      rexmpp_send(s, presence);
    }
    if (! strcmp(word, "approve")) {
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (word == NULL) {
        return;
      }
      presence = rexmpp_xml_new_elem("presence", "jabber:client");
      rexmpp_xml_add_id(s, presence);
      rexmpp_xml_add_attr(presence, "to", word);
      rexmpp_xml_add_attr(presence, "type", "subscribed");
      rexmpp_send(s, presence);
    }
    if (! strcmp(word, "deny")) {
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (word == NULL) {
        return;
      }
      presence = rexmpp_xml_new_elem("presence", "jabber:client");
      rexmpp_xml_add_id(s, presence);
      rexmpp_xml_add_attr(presence, "to",  word);
      rexmpp_xml_add_attr(presence, "type", "unsubscribed");
      rexmpp_send(s, presence);
    }
  }

  if (! strcmp(word, "http-upload")) {
    char *fpath = strtok_r(NULL, " ", &words_save_ptr);
    rexmpp_http_upload_path(s, NULL, fpath, NULL,
                            rexmpp_console_on_upload, strdup(fpath));
  }

  if (! strcmp(word, "jingle")) {
    word = strtok_r(NULL, " ", &words_save_ptr);
    if (word == NULL) {
      return;
    }
    if (! strcmp(word, "terminate")) {
      char *sid = strtok_r(NULL, " ", &words_save_ptr);
      if (sid != NULL) {
        rexmpp_jingle_session_terminate(s, sid,
                                        rexmpp_xml_new_elem("success",
                                                            "urn:xmpp:jingle:1"),
                                        NULL);
      }
    } else if (! strcmp(word, "decline")) {
      char *sid = strtok_r(NULL, " ", &words_save_ptr);
      if (sid != NULL) {
        rexmpp_jingle_session_terminate(s, sid,
                                        rexmpp_xml_new_elem("decline",
                                                            "urn:xmpp:jingle:1"),
                                        NULL);
      }
    } else if (! strcmp(word, "accept-file")) {
      char *sid = strtok_r(NULL, " ", &words_save_ptr);
      char *fpath = strtok_r(NULL, " ", &words_save_ptr);
      if (sid != NULL && fpath != NULL) {
        rexmpp_jingle_accept_file_by_id(s, sid, fpath);
      }
    } else if (! strcmp(word, "send-file")) {
      char *jid = strtok_r(NULL, " ", &words_save_ptr);
      char *fpath = strtok_r(NULL, " ", &words_save_ptr);
      if (jid != NULL && fpath != NULL) {
        rexmpp_jingle_send_file(s, jid, fpath);
      }
    } else if (! strcmp(word, "accept-call")) {
      char *sid = strtok_r(NULL, " ", &words_save_ptr);
      char *port_in = strtok_r(NULL, " ", &words_save_ptr);
      char *port_out = strtok_r(NULL, " ", &words_save_ptr);
      if (sid != NULL && port_in != NULL && port_out != NULL) {
        rexmpp_jingle_call_accept(s, sid, atoi(port_in), atoi(port_out));
      }
    } else if (! strcmp(word, "call")) {
      char *jid = strtok_r(NULL, " ", &words_save_ptr);
      char *port_in = strtok_r(NULL, " ", &words_save_ptr);
      char *port_out = strtok_r(NULL, " ", &words_save_ptr);
      if (jid != NULL && port_in != NULL && port_out != NULL) {
        rexmpp_jingle_call(s, jid, atoi(port_in), atoi(port_out));
      }
    }
  }

  if (! strcmp(word, "disco")) {
    word = strtok_r(NULL, " ", &words_save_ptr);
    if (word == NULL) {
      return;
    }
    if (! strcmp(word, "info")) {
      char *jid = strtok_r(NULL, " ", &words_save_ptr);
      if (jid == NULL) {
        return;
      }
      rexmpp_xml_t *query =
        rexmpp_xml_new_elem("query",
                            "http://jabber.org/protocol/disco#info");
      rexmpp_iq_new(s, "get", jid, query, rexmpp_console_disco_info, NULL);
    }
    if (! strcmp(word, "items")) {
      char *jid = strtok_r(NULL, " ", &words_save_ptr);
      if (jid == NULL) {
        return;
      }
      rexmpp_xml_t *query =
        rexmpp_xml_new_elem("query",
                            "http://jabber.org/protocol/disco#items");
      rexmpp_iq_new(s, "get", jid, query, rexmpp_console_disco_items, NULL);
    }
  }

  if (! strcmp(word, "pubsub")) {
    word = strtok_r(NULL, " ", &words_save_ptr);
    if (word == NULL) {
      return;
    }
    if (! strcmp(word, "node")) {
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (word == NULL) {
        return;
      }
      if (! strcmp(word, "delete")) {
        char *service_jid = strtok_r(NULL, " ", &words_save_ptr);
        char *node = strtok_r(NULL, " ", &words_save_ptr);
        if (service_jid == NULL || node == NULL) {
          return;
        }
        rexmpp_pubsub_node_delete(s, service_jid, node, rexmpp_console_pubsub_node_deleted, NULL);
      }
    }
  }

  if (! strcmp(word, "blocklist")) {
    word = strtok_r(NULL, " ", &words_save_ptr);
    if (word == NULL) {
      rexmpp_xml_t *bl =
        rexmpp_xml_new_elem("blocklist", "urn:xmpp:blocking");
      rexmpp_iq_new(s, "get", NULL, bl, rexmpp_console_blocklist, NULL);
    } else if (! strcmp(word, "block")) {
      char *jid = strtok_r(NULL, " ", &words_save_ptr);
      if (jid == NULL) {
        return;
      }
      rexmpp_xml_t *bl =
        rexmpp_xml_new_elem("block", "urn:xmpp:blocking");
      rexmpp_xml_t *item =
        rexmpp_xml_new_elem("item", "urn:xmpp:blocking");
      rexmpp_xml_add_attr(item, "jid", jid);
      rexmpp_xml_add_child(bl, item);
      rexmpp_iq_new(s, "set", NULL, bl, rexmpp_console_blocklist_blocked, NULL);
    } else if (! strcmp(word, "unblock")) {
      char *jid = strtok_r(NULL, " ", &words_save_ptr);
      if (jid == NULL) {
        return;
      }
      rexmpp_xml_t *bl =
        rexmpp_xml_new_elem("unblock", "urn:xmpp:blocking");
      rexmpp_xml_t *item =
        rexmpp_xml_new_elem("item", "urn:xmpp:blocking");
      rexmpp_xml_add_attr(item, "jid", jid);
      rexmpp_xml_add_child(bl, item);
      rexmpp_iq_new(s, "set", NULL, bl, rexmpp_console_blocklist_unblocked, NULL);
    }
  }
}
