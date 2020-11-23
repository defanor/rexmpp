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
    rexmpp_console_printf(s, "Becoming %s\n",
                          (presence_type == NULL) ?
                          "available" :
                          presence_type);
    if (presence_type != NULL) {
      free(presence_type);
    }
  }
}

void rexmpp_console_on_recv (rexmpp_t *s, xmlNodePtr node) {
  if (rexmpp_xml_match(node, "jabber:client", "message")) {
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
    rexmpp_console_printf(s, "%s is %s\n", from,
                          (presence_type == NULL) ?
                          "available" :
                          presence_type);
    if (presence_type != NULL) {
      free(presence_type);
    }
    if (from != NULL) {
      free(from);
    }
  }
}

void rexmpp_console_on_run (rexmpp_t *s, rexmpp_err_t result) {
  if (result == REXMPP_SUCCESS) {
    rexmpp_console_printf(s, "Done.\n");
    return;
  }
}

void rexmpp_console_feed (rexmpp_t *s, char *str, ssize_t str_len) {
  /* todo: buffering */
  char *words_save_ptr;
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
    "publish-key <fingerprint>\n"
    "join <conference> [as] <nick>\n"
    ;

  if (! strcmp(word, "help")) {
    rexmpp_console_printf(s, help);
  }

  if (! strcmp(word, "quit")) {
    rexmpp_console_printf(s, "Quitting.\n");
    rexmpp_stop(s);
    return;
  }

  if (! strcmp(word, "publish-key")) {
    char *fingerprint = strtok_r(NULL, " ", &words_save_ptr);
    rexmpp_openpgp_publish_key(s, fingerprint);
  }

  if (! strcmp(word, "tell")) {
    jid_str = strtok_r(NULL, " ", &words_save_ptr);
    if (jid_str == NULL || rexmpp_jid_parse(jid_str, &jid)) {
      return;
    }
    msg_text = jid_str + strlen(jid_str) + 1;
    xmlNodePtr msg = rexmpp_xml_add_id(s, xmlNewNode(NULL, "message"));
    xmlNewProp(msg, "to", jid.full);
    xmlNewProp(msg, "type", "chat");
    xmlNewTextChild(msg, NULL, "body", msg_text);
    rexmpp_send(s, msg);
  }

  if (! strcmp(word, "signcrypt")) {
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
    char *b64 = rexmpp_openpgp_encrypt_sign(s, body, rcpt);
    xmlNodePtr openpgp = xmlNewNode(NULL, "openpgp");
    openpgp->ns = xmlNewNs(openpgp, "urn:xmpp:openpgp:0", NULL);
    xmlNodeAddContent(openpgp, b64);
    free(b64);

    xmlNodePtr msg = rexmpp_xml_add_id(s, xmlNewNode(NULL, "message"));
    xmlNewProp(msg, "to", jid.full);
    xmlNewProp(msg, "type", "chat");
    xmlAddChild(msg, openpgp);

    body = xmlNewNode(NULL, "body");
    xmlNewNs(body, "jabber:client", NULL);
    xmlNodeAddContent(body, "This is a secret message.");
    xmlAddChild(msg, body);

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
    xmlNodePtr presence = rexmpp_xml_add_id(s, xmlNewNode(NULL, "presence"));
    xmlNewProp(presence, "from", s->assigned_jid.full);
    xmlNewProp(presence, "to", full_jid);
    xmlNodePtr x = xmlNewNode(NULL, "x");
    xmlNewNs(x, "http://jabber.org/protocol/muc", NULL);
    xmlAddChild(presence, x);
    rexmpp_send(s, presence);
  }
}
