/*
   This is quite messy and should be refactored, but good enough for
   testing.

   Building:

   gcc -fPIC -Wall -Wno-pointer-sign -c `pkg-config --cflags --libs weechat libgsasl libxml-2.0 gnutls rexmpp` examples/weechat.c
   gcc `pkg-config --cflags --libs weechat libgsasl libxml-2.0 gnutls rexmpp` -shared -fPIC -o weechat.so weechat.o
   mv weechat.so ~/.weechat/plugins/rexmpp.so

   Usage:

   Connect: /xmpp <jid> <password>
   Open a chat buffer (from the server buffer): q <jid>
   Join a conference (from the server buffer): j <room>@<server>/<nick>

   TODO:

   - Refine/rethink control/commands.
   - Add settings (SASL parameters and regular rexmpp configuration).
   - Add commands for roster management and other functionality.
   - Refactor the hacky bits of this plugin.
*/

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <libxml/tree.h>
#include "weechat-plugin.h"
#include "rexmpp.h"
#include "rexmpp_roster.h"
#include "rexmpp_jid.h"
#include "rexmpp_openpgp.h"

WEECHAT_PLUGIN_NAME("rexmpp");
WEECHAT_PLUGIN_DESCRIPTION("XMPP plugin using librexmpp");
WEECHAT_PLUGIN_AUTHOR("defanor <defanor@uberspace.net>");
WEECHAT_PLUGIN_VERSION("0.0.0");
WEECHAT_PLUGIN_LICENSE("MIT");

struct weechat_rexmpp {
  rexmpp_t rexmpp_state;
  struct t_gui_buffer *server_buffer;
  char *password;
  struct t_arraylist *hooks;
};

struct weechat_rexmpp_muc {
  struct weechat_rexmpp *wr;
  struct rexmpp_jid jid;
};

struct t_weechat_plugin *weechat_plugin = NULL;

void my_logger (rexmpp_t *s,
                int priority,
                const char *fmt,
                va_list args)
{
  struct weechat_rexmpp *wr = (struct weechat_rexmpp *)s;
  char *priority_str = "unknown";
  switch (priority) {
  case LOG_EMERG: priority_str = "emerg"; break;
  case LOG_ALERT: priority_str = "alert"; break;
  case LOG_CRIT: priority_str = "crit"; break;
  case LOG_ERR: priority_str = "err"; break;
  case LOG_WARNING: priority_str = "warning"; break;
  case LOG_NOTICE: priority_str = "notice"; break;
  case LOG_INFO: priority_str = "info"; break;
  case LOG_DEBUG: priority_str = "debug"; break;
  }
  char buf[4096];

  sprintf(buf, "[%s] ", priority_str);
  vsprintf(buf + strlen(buf), fmt, args);
  weechat_printf(wr->server_buffer, "%s\n", buf);
}

int my_sasl_property_cb (rexmpp_t *s, Gsasl_property prop) {
  struct weechat_rexmpp *wr = (struct weechat_rexmpp *)s;
  if (prop == GSASL_PASSWORD) {
    gsasl_property_set (s->sasl_session, GSASL_PASSWORD, wr->password);
    return GSASL_OK;
  }
  if (prop == GSASL_AUTHID) {
    gsasl_property_set (s->sasl_session, GSASL_AUTHID, s->initial_jid.local);
    return GSASL_OK;
  }
  weechat_printf(wr->server_buffer, "unhandled gsasl property: %d\n", prop);
  return GSASL_NO_CALLBACK;
}

int query_input_cb (const void *ptr, void *data,
                    struct t_gui_buffer *buffer, const char *input_data)
{
  struct weechat_rexmpp *wr = (void*)ptr;
  rexmpp_t *s = &wr->rexmpp_state;
  const char *to = weechat_buffer_get_string(buffer, "name");
  xmlNodePtr msg = rexmpp_xml_add_id(s, xmlNewNode(NULL, "message"));
  xmlNewProp(msg, "to", to);
  xmlNewProp(msg, "type", "chat");
  xmlNewTextChild(msg, NULL, "body", input_data);
  rexmpp_send(s, msg);
  weechat_printf_date_tags(buffer, 0, "self_msg", "%s\t%s\n", ">", input_data);
  return WEECHAT_RC_OK;
}

int query_close_cb (const void *ptr, void *data,
                    struct t_gui_buffer *buffer)
{
  /* struct weechat_rexmpp *wr = (void*)ptr; */
  return WEECHAT_RC_OK;
}

int muc_input_cb (const void *ptr, void *data,
                  struct t_gui_buffer *buffer, const char *input_data)
{
  struct weechat_rexmpp_muc *wrm = (void*)ptr;
  rexmpp_t *s = &wrm->wr->rexmpp_state;
  xmlNodePtr msg = rexmpp_xml_add_id(s, xmlNewNode(NULL, "message"));
  xmlNewProp(msg, "to", wrm->jid.bare);
  xmlNewProp(msg, "type", "groupchat");
  xmlNewTextChild(msg, NULL, "body", input_data);
  rexmpp_send(s, msg);
  return WEECHAT_RC_OK;
}

int muc_close_cb (const void *ptr, void *data,
                    struct t_gui_buffer *buffer)
{
  struct weechat_rexmpp_muc *wrm = (void*)ptr;
  rexmpp_t *s = &wrm->wr->rexmpp_state;
  xmlNodePtr presence = rexmpp_xml_add_id(s, xmlNewNode(NULL, "presence"));
  xmlNewProp(presence, "from", s->assigned_jid.full);
  xmlNewProp(presence, "to", wrm->jid.full);
  xmlNewProp(presence, "type", "unavailable");
  rexmpp_send(s, presence);
  free(wrm);
  return WEECHAT_RC_OK;
}

void display_message (struct t_gui_buffer *buf,
                      const char *display_name,
                      xmlNodePtr body)
{
  xmlChar *str = xmlNodeGetContent(body);
  if (str != NULL) {
    char tags[4096];
    snprintf(tags, 4096, "nick_%s", display_name);
    weechat_printf_date_tags(buf, 0, tags, "%s\t%s\n", display_name, str);
    xmlFree(str);
  }
}

int my_xml_in_cb (rexmpp_t *s, xmlNodePtr node) {
  struct weechat_rexmpp *wr = (struct weechat_rexmpp *)s;
  char *xml_buf = rexmpp_xml_serialize(node);
  weechat_printf(wr->server_buffer, "recv: %s\n", xml_buf);
  /* free(xml_buf); */
  if (rexmpp_xml_match(node, "jabber:client", "message")) {
    char *from = xmlGetProp(node, "from");
    if (from != NULL) {
      struct rexmpp_jid from_jid;
      rexmpp_jid_parse(from, &from_jid);
      xmlFree(from);
      char *display_name = from_jid.full;
      if (from_jid.resource[0]) {
        display_name = from_jid.resource;
      }
      struct t_gui_buffer *buf = weechat_buffer_search("rexmpp", from_jid.bare);
      if (buf == NULL) {
        buf = weechat_buffer_new (from_jid.bare,
                                  &query_input_cb, wr, NULL,
                                  &query_close_cb, wr, NULL);
        weechat_buffer_set(buf, "nicklist", "1");
      }
      xmlNodePtr body = rexmpp_xml_find_child(node, "jabber:client", "body");

      xmlNodePtr openpgp = rexmpp_xml_find_child(node, "urn:xmpp:openpgp:0", "openpgp");
      if (openpgp != NULL) {
        int valid;
        xmlNodePtr elem = rexmpp_openpgp_decrypt_verify_message(s, node, &valid);
        if (! valid) {
          weechat_printf(buf, "An invalid OpenPGP message!");
        }

        if (elem != NULL) {
          xmlNodePtr payload =
            rexmpp_xml_find_child(elem, "urn:xmpp:openpgp:0", "payload");
          if (payload != NULL) {
            xmlNodePtr pl_body =
              rexmpp_xml_find_child(payload, "jabber:client", "body");
            if (pl_body != NULL) {
              display_message(buf, display_name, pl_body);
              body = NULL;
            }
          }
          xmlFreeNode(elem);
        }
      }

      if (body != NULL) {
        display_message(buf, display_name, body);
      }
    }
  }
  if (rexmpp_xml_match(node, "jabber:client", "presence")) {
    char *presence_type = xmlGetProp(node, "type");
    char *from = xmlGetProp(node, "from");
    struct rexmpp_jid from_jid;
    rexmpp_jid_parse(from, &from_jid);
    xmlFree(from);

    xmlNodePtr muc =
      rexmpp_xml_find_child(node, "http://jabber.org/protocol/muc#user", "x");
    if (muc != NULL) {

      /* Handle newly joined MUCs */
      if (presence_type == NULL) {
        xmlNodePtr status =
          rexmpp_xml_find_child(muc, "http://jabber.org/protocol/muc#user",
                                "status");
        if (status != NULL) {
          char *code = xmlGetProp(status, "code");
          if (code != NULL) {
            if (strcmp(code, "110") == 0) {
              struct weechat_rexmpp_muc *wrm =
                malloc(sizeof(struct weechat_rexmpp_muc));
              wrm->wr = wr;
              rexmpp_jid_parse(from_jid.full, &(wrm->jid));
              struct t_gui_buffer *buf =
                weechat_buffer_search("rexmpp", wrm->jid.bare);
              if (buf == NULL) {
                buf = weechat_buffer_new (wrm->jid.bare,
                                          &muc_input_cb, wrm, NULL,
                                          &muc_close_cb, wrm, NULL);
                weechat_buffer_set(buf, "nicklist", "1");
              }
            }
            free(code);
          }
        }
      }

      /* Update MUC nicklist */
      struct t_gui_buffer *buf = weechat_buffer_search("rexmpp", from_jid.bare);
      if (buf != NULL) {
        if (presence_type != NULL && strcmp(presence_type, "unavailable") == 0) {
          struct t_gui_nick *nick =
            weechat_nicklist_search_nick(buf, NULL, from_jid.resource);
          if (nick != NULL) {
            weechat_nicklist_remove_nick(buf, nick);
          }
        } else {
          weechat_nicklist_add_nick(buf, NULL, from_jid.resource,
                                    "bar_fg", "", "lightgreen", 1);
        }
      }
    } else if (rexmpp_roster_find_item(s, from_jid.bare, NULL) != NULL) {
      /* A roster item. */
      struct t_gui_nick *nick = weechat_nicklist_search_nick(wr->server_buffer, NULL, from_jid.bare);
      if (presence_type == NULL) {
        /* An "available" presence: just ensure that it's shown as
           online. */
        weechat_nicklist_nick_set(wr->server_buffer, nick, "prefix", "+");
      } else if (strcmp(presence_type, "unavailable") == 0) {
        /* An "unavailable" presence: set it to "offline" if there's
           no remaining online resources (i.e., if we can find an
           online resource for this bare JID other than the one that
           just went offline). */
        xmlNodePtr cur;
        int found = 0;
        struct rexmpp_jid cur_from_jid;
        for (cur = s->roster_presence;
             cur != NULL;
             cur = xmlNextElementSibling(cur)) {
          char *cur_from = xmlGetProp(cur, "from");
          rexmpp_jid_parse(cur_from, &cur_from_jid);
          xmlFree(cur_from);
          if (strcmp(cur_from_jid.bare, from_jid.bare) == 0 &&
              strcmp(cur_from_jid.resource, from_jid.resource) != 0) {
            found = 1;
          }
        }
        if (! found) {
          weechat_nicklist_nick_set(wr->server_buffer, nick, "prefix", "");
        }
      }
    }
    if (presence_type != NULL) {
      free(presence_type);
    }
  }
  free(xml_buf);
  return 0;
}

int my_xml_out_cb (rexmpp_t *s, xmlNodePtr node) {
  struct weechat_rexmpp *wr = (struct weechat_rexmpp *)s;
  char *xml_buf = rexmpp_xml_serialize(node);
  weechat_printf(wr->server_buffer, "send: %s\n", xml_buf);
  free(xml_buf);
  return 0;
}

void my_console_print_cb (struct weechat_rexmpp *wr, const char *fmt, va_list args) {
  char str[4096];
  vsnprintf(str, 4096, fmt, args);
  weechat_printf(wr->server_buffer, "%s", str);
}

int
my_input_cb (const void *ptr, void *data,
             struct t_gui_buffer *buffer, const char *input_data)
{
  struct weechat_rexmpp *wr = (void*)ptr;
  rexmpp_t *s = &wr->rexmpp_state;
  if (input_data[0] == '<') {
    xmlDocPtr doc = xmlReadMemory(input_data, strlen(input_data), "", "utf-8", 0);
    if (doc != NULL) {
      xmlNodePtr node = xmlDocGetRootElement(doc);
      if (node != NULL) {
        xmlUnlinkNode(node);
        rexmpp_send(s, node);
      } else {
        weechat_printf(buffer, "No root node\n");
      }
      xmlFreeDoc(doc);
    } else {
      weechat_printf(buffer, "Failed to read a document\n");
    }
  } else if (input_data[0] == 'q' && input_data[1] == ' ') {
    const char *jid = input_data + 2;
    struct t_gui_buffer *buf = weechat_buffer_search("rexmpp", jid);
    if (buf == NULL) {
      buf = weechat_buffer_new (jid,
                                &query_input_cb, wr, NULL,
                                &query_close_cb, wr, NULL);
      weechat_buffer_set(buf, "nicklist", "1");
    }
  } else {
    rexmpp_console_feed(s, input_data, strlen(input_data));
  }
  return WEECHAT_RC_OK;
}

void my_roster_modify_cb (rexmpp_t *s, xmlNodePtr item) {
  struct weechat_rexmpp *wr = (struct weechat_rexmpp *)s;
  char *subscription = xmlGetProp(item, "subscription");
  char *jid = xmlGetProp(item, "jid");
  if (subscription != NULL && strcmp(subscription, "remove") == 0) {
    /* delete */
    struct t_gui_nick *nick = weechat_nicklist_search_nick(wr->server_buffer, NULL, jid);
    if (nick != NULL) {
      weechat_nicklist_remove_nick(wr->server_buffer, nick);
    }
  } else {
    /* add or modify */
    weechat_nicklist_add_nick(wr->server_buffer, NULL, jid,
                              "bar_fg", "", "lightgreen", 1);
  }
  free(jid);
  if (subscription != NULL) {
    free(subscription);
  }
}

int
my_close_cb (const void *ptr, void *data, struct t_gui_buffer *buffer)
{
  /* todo: close MUC buffers first? or at least mark them somehow, so
     that they won't attempt to send "unavailable" presence on
     closing. */
  struct weechat_rexmpp *wr = (void*)ptr;
  wr->server_buffer = NULL;
  rexmpp_stop(&wr->rexmpp_state);
  return WEECHAT_RC_OK;
}

void iter (struct weechat_rexmpp *wr, fd_set *rfds, fd_set *wfds);

int fd_read_cb (const void *ptr, void *data, int fd) {
  struct weechat_rexmpp *wr = (void*)ptr;
  /* weechat_printf(wr->server_buffer, "read hook fired"); */
  fd_set read_fds, write_fds;
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  FD_SET(fd, &read_fds);
  iter(wr, &read_fds, &write_fds);
  return 0;
}

int fd_write_cb (const void *ptr, void *data, int fd) {
  struct weechat_rexmpp *wr = (void*)ptr;
  /* weechat_printf(wr->server_buffer, "write hook fired"); */
  fd_set read_fds, write_fds;
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  FD_SET(fd, &write_fds);
  iter(wr, &read_fds, &write_fds);
  return 0;
}

int timer_cb (const void *ptr, void *data, int remaining_calls) {
  struct weechat_rexmpp *wr = (void*)ptr;
  /* weechat_printf(wr->server_buffer, "timer hook fired"); */
  fd_set read_fds, write_fds;
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  iter(wr, &read_fds, &write_fds);
  return 0;
}

void hook_free_cb (void *data, struct t_arraylist *arraylist, void *hook) {
  weechat_unhook((struct t_hook *)hook);
}

void iter (struct weechat_rexmpp *wr, fd_set *rfds, fd_set *wfds) {
  rexmpp_t *s = &wr->rexmpp_state;

  /* cleanup old hooks */
  /* weechat_printf(wr->server_buffer, "-- hooks removed --"); */
  weechat_arraylist_clear(wr->hooks);

  rexmpp_err_t err;
  err = rexmpp_run(s, rfds, wfds);
  if (err == REXMPP_SUCCESS) {
    free(wr->password);
    rexmpp_done(&wr->rexmpp_state);
    weechat_arraylist_free(wr->hooks);
    free(wr);
    return;
  }
  if (err != REXMPP_E_AGAIN) {
    weechat_printf(wr->server_buffer, "rexmpp error");
    return;
  }
  fd_set read_fds, write_fds;
  int nfds;
  struct timeval tv;
  struct timeval *mtv;
  int i;
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  nfds = rexmpp_fds(s, &read_fds, &write_fds);
  mtv = rexmpp_timeout(s, NULL, (struct timeval*)&tv);

  for (i = 0; i < nfds; i++) {
    if (FD_ISSET(i, &read_fds)) {
      /* weechat_printf(wr->server_buffer, "read hook set"); */
      weechat_arraylist_add(wr->hooks,
                            weechat_hook_fd(i, 1, 0, 0, fd_read_cb, wr, NULL));
    }
    if (FD_ISSET(i, &write_fds)) {
      /* weechat_printf(wr->server_buffer, "write hook set"); */
      weechat_arraylist_add(wr->hooks,
                            weechat_hook_fd(i, 0, 1, 0, fd_write_cb, wr, NULL));
    }
  }
  if (mtv != NULL) {
    /* weechat_printf(wr->server_buffer, "timer hook set: %d %d\n", mtv->tv_sec, mtv->tv_sec); */
    int t = mtv->tv_sec * 1000 + mtv->tv_sec / 1000;
    if (t == 0) {
      /* A hack, since at 0 weechat won't fire a hook. */
      t = 1;
    }
    weechat_arraylist_add(wr->hooks,
                          weechat_hook_timer(t, 0, 1, timer_cb, wr, NULL));
  }
}

int
command_sc_cb (const void *wr_ptr, void *data,
               struct t_gui_buffer *buffer,
               int argc, char **argv, char **argv_eol)
{
  struct weechat_rexmpp *wr = (void*)wr_ptr;
  rexmpp_t *s = &wr->rexmpp_state;
  const char *to = weechat_buffer_get_string(buffer, "name");
  xmlNodePtr body = xmlNewNode(NULL, "body");
  xmlNewNs(body, "jabber:client", NULL);
  xmlNodeAddContent(body, argv_eol[1]);

  const char *rcpt[2];
  rcpt[0] = to;
  rcpt[1] = NULL;

  char *b64 = rexmpp_openpgp_encrypt_sign(s, body, rcpt);
  if (b64 == NULL) {
    weechat_printf(buffer, "Failed to encrypt a message.");
    return WEECHAT_RC_OK;
  }

  xmlNodePtr openpgp = xmlNewNode(NULL, "openpgp");
  xmlNewNs(openpgp, "urn:xmpp:openpgp:0", NULL);
  xmlNodeAddContent(openpgp, b64);
  free(b64);

  xmlNodePtr msg = rexmpp_xml_add_id(s, xmlNewNode(NULL, "message"));
  xmlNewProp(msg, "to", to);
  xmlNewProp(msg, "type", "chat");
  xmlAddChild(msg, openpgp);

  body = xmlNewNode(NULL, "body");
  xmlNewNs(body, "jabber:client", NULL);
  xmlNodeAddContent(body, "This is a secret message.");
  xmlAddChild(msg, body);

  /* XEP-0380: Explicit Message Encryption */
  xmlNodePtr eme = xmlNewNode(NULL, "encryption");
  xmlNewNs(eme, "urn:xmpp:eme:0", NULL);
  xmlNewProp(eme, "namespace", "urn:xmpp:openpgp:0");
  xmlAddChild(msg, eme);

  rexmpp_send(s, msg);
  weechat_printf_date_tags(buffer, 0, "self_msg", "%s\t%s\n", ">", argv_eol[1]);
  return WEECHAT_RC_OK;
}

int
command_xmpp_cb (const void *pointer, void *data,
                 struct t_gui_buffer *buffer,
                 int argc, char **argv, char **argv_eol)
{
  if (argc == 3) {
    struct weechat_rexmpp *wr = malloc(sizeof(struct weechat_rexmpp));
    wr->server_buffer = weechat_buffer_new (argv[1],
                                            &my_input_cb, wr, NULL,
                                            &my_close_cb, wr, NULL);
    weechat_buffer_set(wr->server_buffer, "nicklist", "1");
    wr->password = strdup(argv[2]);
    wr->hooks = weechat_arraylist_new(42, 0, 0, NULL, NULL, hook_free_cb, NULL);
    rexmpp_t *s = &wr->rexmpp_state;
    rexmpp_init(s, argv[1]);
    s->log_function = my_logger;
    s->sasl_property_cb = my_sasl_property_cb;
    s->xml_in_cb = my_xml_in_cb;
    s->xml_out_cb = my_xml_out_cb;
    s->roster_modify_cb = my_roster_modify_cb;
    s->console_print_cb = my_console_print_cb;
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    iter(wr, &read_fds, &write_fds);

    weechat_hook_command ("sc",
                          "Sign and encrypt a message",
                          "<message>",
                          "message: a message to send",
                          NULL,
                          &command_sc_cb, wr, NULL);
  }
  return WEECHAT_RC_OK;
}

int
weechat_plugin_init (struct t_weechat_plugin *plugin,
                     int argc, char *argv[])
{
  weechat_plugin = plugin;

  weechat_hook_command ("xmpp",
                        "Initialise an XMPP session",
                        "<jid> <password>",
                        "jid: JID\npassword: password",
                        NULL,
                        &command_xmpp_cb, NULL, NULL);

  return WEECHAT_RC_OK;
}

int
weechat_plugin_end (struct t_weechat_plugin *plugin)
{
    return WEECHAT_RC_OK;
}
