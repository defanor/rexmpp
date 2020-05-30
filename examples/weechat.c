/* This is quite messy and should be refactored, but good enough for
   testing. */

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "weechat-plugin.h"
#include "rexmpp.h"

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

struct t_weechat_plugin *weechat_plugin = NULL;

void my_logger (const struct weechat_rexmpp *wr,
                int priority,
                const char *fmt,
                va_list args)
{
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

int my_sasl_property_cb (const struct weechat_rexmpp *wr, Gsasl_property prop) {
  rexmpp_t *s = &wr->rexmpp_state;
  if (prop == GSASL_PASSWORD) {
    gsasl_property_set (s->sasl_session, GSASL_PASSWORD, wr->password);
    return GSASL_OK;
  }
  if (prop == GSASL_AUTHID) {
    char *domainpart = strchr(s->initial_jid, '@');
    if (domainpart != NULL) {
      int localpart_len = domainpart - s->initial_jid;
      char *localpart = malloc(localpart_len + 1);
      localpart[localpart_len] = 0;
      strncpy(localpart, s->initial_jid, localpart_len);
      gsasl_property_set (s->sasl_session, GSASL_AUTHID, localpart);
      free(localpart);
      return GSASL_OK;
    }
  }
  weechat_printf(wr->server_buffer, "unhandled gsasl property: %d\n", prop);
  return GSASL_NO_CALLBACK;
}

int
query_input_cb (const struct weechat_rexmpp *wr, void *data,
             struct t_gui_buffer *buffer, const char *input_data)
{
  rexmpp_t *s = &wr->rexmpp_state;
  char *to = weechat_buffer_get_string(buffer, "name");
  xmlNodePtr msg = rexmpp_xml_add_id(s, xmlNewNode(NULL, "message"));
  xmlNewProp(msg, "to", to);
  xmlNewProp(msg, "type", "chat");
  xmlNewTextChild(msg, NULL, "body", input_data);
  rexmpp_send(s, msg);
  weechat_printf(buffer, "%s: %s\n", s->initial_jid, input_data);
  return WEECHAT_RC_OK;
}

int
query_close_cb (struct weechat_rexmpp *wr, void *data, struct t_gui_buffer *buffer)
{
  return WEECHAT_RC_OK;
}

int my_xml_in_cb (struct weechat_rexmpp *wr, xmlNodePtr node) {
  char *xml_buf = rexmpp_xml_serialize(node);
  weechat_printf(wr->server_buffer, "recv: %s\n", xml_buf);
  /* free(xml_buf); */
  if (rexmpp_xml_match(node, "jabber:client", "message")) {
    char *from = xmlGetProp(node, "from");
    int i;
    for (i = 0; i < strlen(from); i++) {
      if (from[i] == '/') {
        from[i] = 0;
        break;
      }
    }
    if (from != NULL) {
      struct t_gui_buffer *buf = weechat_buffer_search("rexmpp", from);
      if (buf == NULL) {
        buf = weechat_buffer_new (from,
                                  &query_input_cb, wr, NULL,
                                  &query_close_cb, wr, NULL);
      }
      xmlNodePtr body = rexmpp_xml_find_child(node, "jabber:client", "body");
      if (body != NULL) {
        xmlChar *str = xmlNodeGetContent(body);
        if (str != NULL) {
          weechat_printf(buf, "%s: %s\n", from, str);
          xmlFree(str);
        }
      }
      xmlFree(from);
    }
  }
  free(xml_buf);
  return 0;
}

int my_xml_out_cb (struct weechat_rexmpp *wr, xmlNodePtr node) {
  char *xml_buf = rexmpp_xml_serialize(node);
  weechat_printf(wr->server_buffer, "send: %s\n", xml_buf);
  free(xml_buf);
  return 0;
}

int
my_input_cb (const struct weechat_rexmpp *wr, void *data,
             struct t_gui_buffer *buffer, const char *input_data)
{
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
    char *jid = input_data + 2;
    struct t_gui_buffer *buf = weechat_buffer_search("rexmpp", jid);
    if (buf == NULL) {
      buf = weechat_buffer_new (jid,
                                &query_input_cb, wr, NULL,
                                &query_close_cb, wr, NULL);
    }
  }
  return WEECHAT_RC_OK;
}

int
my_close_cb (struct weechat_rexmpp *wr, void *data, struct t_gui_buffer *buffer)
{
  wr->server_buffer = NULL;
  rexmpp_stop(&wr->rexmpp_state);
  return WEECHAT_RC_OK;
}

void iter (struct weechat_rexmpp *wr, fd_set *rfds, fd_set *wfds);

int fd_read_cb (const struct weechat_rexmpp *wr, void *data, int fd) {
  /* weechat_printf(wr->server_buffer, "read hook fired"); */
  fd_set read_fds, write_fds;
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  FD_SET(fd, &read_fds);
  iter(wr, &read_fds, &write_fds);
  return 0;
}

int fd_write_cb (const struct weechat_rexmpp *wr, void *data, int fd) {
  /* weechat_printf(wr->server_buffer, "write hook fired"); */
  fd_set read_fds, write_fds;
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  FD_SET(fd, &write_fds);
  iter(wr, &read_fds, &write_fds);
  return 0;
}

int timer_cb (const struct weechat_rexmpp *wr, void *data, int remaining_calls) {
  /* weechat_printf(wr->server_buffer, "timer hook fired"); */
  fd_set read_fds, write_fds;
  FD_ZERO(&read_fds);
  FD_ZERO(&write_fds);
  iter(wr, &read_fds, &write_fds);
  return 0;
}

void hook_free_cb (void *data, struct t_arraylist *arraylist, struct t_hook *hook) {
  weechat_unhook(hook);
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
command_xmpp_cb (const void *pointer, void *data,
                 struct t_gui_buffer *buffer,
                 int argc, char **argv, char **argv_eol)
{
  if (argc == 3) {
    struct weechat_rexmpp *wr = malloc(sizeof(struct weechat_rexmpp));
    wr->server_buffer = weechat_buffer_new (argv[1],
                                            &my_input_cb, wr, NULL,
                                            &my_close_cb, wr, NULL);
    wr->password = strdup(argv[2]);
    wr->hooks = weechat_arraylist_new(42, 0, 0, NULL, NULL, hook_free_cb, NULL);
    rexmpp_t *s = &wr->rexmpp_state;
    rexmpp_init(s, argv[1]);
    s->log_function = my_logger;
    s->sasl_property_cb = my_sasl_property_cb;
    s->xml_in_cb = my_xml_in_cb;
    s->xml_out_cb = my_xml_out_cb;
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    iter(wr, &read_fds, &write_fds);
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
