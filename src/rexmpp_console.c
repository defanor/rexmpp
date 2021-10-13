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
#include "rexmpp_openpgp.h"
#include "rexmpp_http_upload.h"
#include "rexmpp_jingle.h"
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

char *rexmpp_console_message_string (rexmpp_t *s, xmlNodePtr node) {
  char *ret = NULL;
  xmlNodePtr openpgp =
    rexmpp_xml_find_child(node, "urn:xmpp:openpgp:0", "openpgp");
  if (openpgp != NULL) {
    int valid;
    xmlNodePtr elem = rexmpp_openpgp_decrypt_verify_message(s, node, &valid);
    if (! valid) {
      rexmpp_console_printf(s, "An invalid OpenPGP message!\n");
    }

    if (elem != NULL) {
      xmlNodePtr payload =
        rexmpp_xml_find_child(elem, "urn:xmpp:openpgp:0", "payload");
      if (payload != NULL) {
        xmlNodePtr pl_body =
          rexmpp_xml_find_child(payload, "jabber:client", "body");
        if (pl_body != NULL) {
          ret = xmlNodeGetContent(pl_body);
        }
      }
      xmlFreeNode(elem);
    }
  }
  if (ret == NULL) {
    xmlNodePtr body = rexmpp_xml_find_child(node, "jabber:client", "body");
    ret = xmlNodeGetContent(body);
  }
  return ret;
}

void rexmpp_console_on_send (rexmpp_t *s, xmlNodePtr node) {
  if (rexmpp_xml_match(node, "jabber:client", "message")) {
    char *to = xmlGetProp(node, "to");
    if (to != NULL) {
      /* "from" should be set for verification. */
      char *from = xmlGetProp(node, "from");
      xmlAttrPtr fromProp = NULL;
      if (from == NULL) {
        fromProp = xmlNewProp(node, "from", to);
      }
      char *str = rexmpp_console_message_string(s, node);
      if (fromProp != NULL) {
        xmlRemoveProp(fromProp);
      }
      if (str != NULL) {
        rexmpp_console_printf(s, "You tell %s: %s\n", to, str);
        free(str);
      }
      free(to);
    }
  }
  if (rexmpp_xml_match(node, "jabber:client", "presence")) {
    char *presence_type = xmlGetProp(node, "type");
    char *presence_to = xmlGetProp(node, "to");
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
      free(presence_to);
    }
    if (presence_type != NULL) {
      free(presence_type);
    }
  }
}

void rexmpp_console_on_recv (rexmpp_t *s, xmlNodePtr node) {
  if (rexmpp_xml_match(node, "jabber:client", "message")) {
    xmlNodePtr sent = rexmpp_xml_find_child(node, "urn:xmpp:carbons:2", "sent");
    if (sent != NULL) {
      xmlNodePtr fwd =
        rexmpp_xml_find_child(sent, "urn:xmpp:forward:0", "forwarded");
      if (fwd != NULL) {
        xmlNodePtr msg =
          rexmpp_xml_find_child(fwd, "jabber:client", "message");
        if (msg != NULL) {
          char *to = xmlGetProp(msg, "to");
          char *str = rexmpp_console_message_string(s, msg);
          if (str != NULL) {
            rexmpp_console_printf(s, "You tell %s: %s\n", to, str);
            free(str);
          }
          if (to != NULL) {
            free(to);
          }
        }
      }
    }

    xmlNodePtr received =
      rexmpp_xml_find_child(node, "urn:xmpp:carbons:2", "received");
    if (received != NULL) {
      xmlNodePtr fwd =
        rexmpp_xml_find_child(received, "urn:xmpp:forward:0", "forwarded");
      if (fwd != NULL) {
        xmlNodePtr msg =
          rexmpp_xml_find_child(fwd, "jabber:client", "message");
        if (msg != NULL) {
          char *from = xmlGetProp(msg, "from");
          char *str = rexmpp_console_message_string(s, msg);
          if (str != NULL) {
            rexmpp_console_printf(s, "%s tells you: %s\n", from, str);
            free(str);
          }
          if (from != NULL) {
            free(from);
          }
        }
      }
    }

    char *from = xmlGetProp(node, "from");
    if (from != NULL) {
      char *str = rexmpp_console_message_string(s, node);
      if (str != NULL) {
        rexmpp_console_printf(s, "%s tells you: %s\n", from, str);
        free(str);
      }
      free(from);
    }
  }
  if (rexmpp_xml_match(node, "jabber:client", "presence")) {
    char *presence_type = xmlGetProp(node, "type");
    char *from = xmlGetProp(node, "from");
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
      xmlNodePtr show = rexmpp_xml_find_child(node, "jabber:client", "show");
      if (show != NULL) {
        char *show_str = xmlNodeGetContent(show);
        rexmpp_console_printf(s, " (%s)", show_str);
        free(show_str);
        show_str = NULL;
      }
      xmlNodePtr status = rexmpp_xml_find_child(node, "jabber:client", "status");
      if (status != NULL) {
        char *status_str = xmlNodeGetContent(status);
        rexmpp_console_printf(s, ": %s", status_str);
        free(status_str);
        status_str = NULL;
      }
      rexmpp_console_printf(s, "\n");
    }
    if (presence_type != NULL) {
      free(presence_type);
    }
    if (from != NULL) {
      free(from);
    }
  }
}


void rexmpp_console_roster_deleted (rexmpp_t *s,
                                    void *ptr,
                                    xmlNodePtr req,
                                    xmlNodePtr response,
                                    int success)
{
  (void)ptr;
  (void)response;
  xmlNodePtr item =
    rexmpp_xml_find_child(rexmpp_xml_find_child(req,
                                                "jabber:iq:roster",
                                                "query"),
                          "jabber:iq:roster", "item");
  char *jid = xmlGetProp(item, "jid");
  if (success) {
    rexmpp_console_printf(s, "Deleted %s from the roster.\n", jid);
  } else {
    rexmpp_console_printf(s, "Failed to delete %s from the roster.\n", jid);
  }
  free(jid);
}

void rexmpp_console_roster_added (rexmpp_t *s,
                                  void *ptr,
                                  xmlNodePtr req,
                                  xmlNodePtr response,
                                  int success)
{
  (void)ptr;
  (void)response;
  xmlNodePtr item =
    rexmpp_xml_find_child(rexmpp_xml_find_child(req,
                                                "jabber:iq:roster",
                                                "query"),
                          "jabber:iq:roster", "item");
  char *jid = xmlGetProp(item, "jid");
  if (success) {
    rexmpp_console_printf(s, "Added %s into the roster.\n", jid);
  } else {
    rexmpp_console_printf(s, "Failed to add %s into the roster.\n", jid);
  }
  free(jid);
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

void rexmpp_console_feed (rexmpp_t *s, char *str, ssize_t str_len) {
  /* todo: buffering */
  (void)str_len;                /* Unused for now (todo). */
  char *words_save_ptr;
  xmlNodePtr presence;
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
    xmlNodePtr msg = rexmpp_xml_add_id(s, xmlNewNode(NULL, "message"));
    xmlNewNs(msg, "jabber:client", NULL);
    xmlNewProp(msg, "to", jid.full);
    xmlNewProp(msg, "type", "chat");
    xmlNewTextChild(msg, NULL, "body", msg_text);
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
    xmlNodePtr body = xmlNewNode(NULL, "body");
    xmlNewNs(body, "jabber:client", NULL);
    xmlNodeAddContent(body, msg_text);
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
    xmlNodePtr openpgp = xmlNewNode(NULL, "openpgp");
    openpgp->ns = xmlNewNs(openpgp, "urn:xmpp:openpgp:0", NULL);
    xmlNodeAddContent(openpgp, b64);
    free(b64);

    xmlNodePtr msg = rexmpp_xml_add_id(s, xmlNewNode(NULL, "message"));
    xmlNewNs(msg, "jabber:client", NULL);
    xmlNewProp(msg, "to", jid.full);
    xmlNewProp(msg, "type", "chat");
    xmlAddChild(msg, openpgp);

    body = xmlNewNode(NULL, "body");
    xmlNewNs(body, "jabber:client", NULL);
    xmlNodeAddContent(body, "This is a secret message.");
    xmlAddChild(msg, body);

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
      xmlNodePtr msg = rexmpp_xml_add_id(s, xmlNewNode(NULL, "message"));
      xmlNewNs(msg, "jabber:client", NULL);
      xmlNewProp(msg, "to", jid.full);
      xmlNewProp(msg, "type", "groupchat");
      xmlNewTextChild(msg, NULL, "body", msg_text);
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
      presence = rexmpp_xml_add_id(s, xmlNewNode(NULL, "presence"));
      xmlNewProp(presence, "from", s->assigned_jid.full);
      xmlNewProp(presence, "to", full_jid);
      xmlNodePtr x = xmlNewNode(NULL, "x");
      xmlNewNs(x, "http://jabber.org/protocol/muc", NULL);
      xmlAddChild(presence, x);
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
      presence = rexmpp_xml_add_id(s, xmlNewNode(NULL, "presence"));
      xmlNewProp(presence, "from", s->assigned_jid.full);
      xmlNewProp(presence, "to", full_jid);
      xmlNewProp(presence, "type", "unavailable");
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
      xmlNodePtr item;
      for (item = s->roster_items;
           item != NULL;
           item = xmlNextElementSibling(item)) {
        char *item_jid = xmlGetProp(item, "jid");
        char *item_ask = xmlGetProp(item, "ask");
        char *item_subscription = xmlGetProp(item, "subscription");
        char *item_presence = "unavailable";
        if (s->track_roster_presence) {
          for (presence = s->roster_presence;
               presence != NULL;
               presence = xmlNextElementSibling(presence)) {
            char *presence_from = xmlGetProp(presence, "from");
            if (presence_from != NULL) {
              rexmpp_jid_parse(presence_from, &jid);
              if (! strcmp(jid.bare, item_jid)) {
                item_presence = "available";
              }
              free(presence_from);
            }
          }
        }
        rexmpp_console_printf(s,
                              "%s: subscription = %s, ask = %s, "
                              "presence = %s\n",
                              item_jid, item_subscription, item_ask,
                              item_presence);
        if (item_jid != NULL) {
          free(item_jid);
        }
        if (item_ask != NULL) {
          free(item_ask);
        }
        if (item_subscription != NULL) {
          free(item_subscription);
        }
      }
    } else if (! strcmp(word, "delete")) {
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (word == NULL) {
        return;
      }
      xmlNodePtr delete_item = xmlNewNode(NULL, "item");
      delete_item->ns = xmlNewNs(delete_item, "jabber:iq:roster", NULL);
      xmlNewProp(delete_item, "jid", word);
      xmlNewProp(delete_item, "subscription", "remove");
      xmlNodePtr delete_query = xmlNewNode(NULL, "query");
      delete_query->ns = xmlNewNs(delete_query, "jabber:iq:roster", NULL);
      xmlAddChild(delete_query, delete_item);
      rexmpp_iq_new(s, "set", NULL, delete_query,
                    rexmpp_console_roster_deleted, NULL);
    } else if (! strcmp(word, "add")) {
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (word == NULL) {
        return;
      }
      xmlNodePtr delete_item = xmlNewNode(NULL, "item");
      delete_item->ns = xmlNewNs(delete_item, "jabber:iq:roster", NULL);
      xmlNewProp(delete_item, "jid", word);
      xmlNodePtr delete_query = xmlNewNode(NULL, "query");
      delete_query->ns = xmlNewNs(delete_query, "jabber:iq:roster", NULL);
      xmlAddChild(delete_query, delete_item);
      rexmpp_iq_new(s, "set", NULL, delete_query,
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
      presence = rexmpp_xml_add_id(s, xmlNewNode(NULL, "presence"));
      xmlNewProp(presence, "to", word);
      xmlNewProp(presence, "type", "subscribe");
      rexmpp_send(s, presence);
    }
    if (! strcmp(word, "approve")) {
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (word == NULL) {
        return;
      }
      presence = rexmpp_xml_add_id(s, xmlNewNode(NULL, "presence"));
      xmlNewProp(presence, "to", word);
      xmlNewProp(presence, "type", "subscribed");
      rexmpp_send(s, presence);
    }
    if (! strcmp(word, "deny")) {
      word = strtok_r(NULL, " ", &words_save_ptr);
      if (word == NULL) {
        return;
      }
      presence = rexmpp_xml_add_id(s, xmlNewNode(NULL, "presence"));
      xmlNewProp(presence, "to", word);
      xmlNewProp(presence, "type", "unsubscribed");
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
                                        rexmpp_xml_new_node("success",
                                                            "urn:xmpp:jingle:1"),
                                        NULL);
      }
    } else if (! strcmp(word, "decline")) {
      char *sid = strtok_r(NULL, " ", &words_save_ptr);
      if (sid != NULL) {
        rexmpp_jingle_session_terminate(s, sid,
                                        rexmpp_xml_new_node("decline",
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
}
