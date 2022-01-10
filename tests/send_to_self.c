/**
   @file send_to_self.c
   @brief A basic message sending test
   @author defanor <defanor@uberspace.net>
   @date 2022
   @copyright MIT license.

Connects to a server, sends a message to itself, receives it, checks
that it's the expected message.

*/

#define TIMEOUT 30

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <gsasl.h>
#include <rexmpp.h>
#include <rexmpp_sasl.h>

enum test_stage {
  TEST_CONNECTING,
  TEST_MESSAGE_SENT,
  TEST_MESSAGE_RECEIVED,
  TEST_DONE,
  TEST_TIMEOUT
};

enum test_stage stage = TEST_CONNECTING;
char *jid, *pass, msg_text[256];

void my_logger (rexmpp_t *s, int priority, const char *fmt, va_list args) {
  (void)s;
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
  fprintf(stdout, "[%s] ", priority_str);
  vfprintf(stdout, fmt, args);
  fprintf(stdout, "\n");
}

int my_sasl_property_cb (rexmpp_t *s, rexmpp_sasl_property prop) {
  if (prop == REXMPP_SASL_PROP_PASSWORD) {
    rexmpp_sasl_property_set (s, REXMPP_SASL_PROP_PASSWORD, pass);
    return 0;
  }
  if (prop == REXMPP_SASL_PROP_AUTHID) {
    rexmpp_sasl_property_set (s, REXMPP_SASL_PROP_AUTHID, s->initial_jid.local);
    return 0;
  }
  printf("unhandled SASL property: %d\n", prop);
  return -1;
}

int my_xml_in_cb (rexmpp_t *s, xmlNodePtr node) {
  (void)s;
  char *xml_buf = rexmpp_xml_serialize(node);
  printf("recv: %s\n", xml_buf);
  free(xml_buf);
  if (stage == TEST_MESSAGE_SENT && rexmpp_xml_match(node, "jabber:client", "message")) {
    xmlNodePtr body = rexmpp_xml_find_child(node, "jabber:client", "body");
    if (body != NULL) {
      char *txt = xmlNodeGetContent(body);
      if (txt != NULL) {
        if (strcmp(txt, msg_text) == 0) {
          stage = TEST_MESSAGE_RECEIVED;
        }
        free(txt);
      }
    }
  }
  return 0;
}

int my_xml_out_cb (rexmpp_t *s, xmlNodePtr node) {
  (void)s;
  char *xml_buf = rexmpp_xml_serialize(node);
  printf("send: %s\n", xml_buf);
  free(xml_buf);
  return 0;
}

int main (int argc, char **argv) {
  (void)argc;
  (void)argv;
  jid = getenv("JID");
  pass = getenv("PASS");
  char *tls_policy = getenv("TLS_POLICY");

  time_t t = time(NULL);
  struct tm utc_time;
  gmtime_r(&t, &utc_time);
  strftime(msg_text, 256, "The current time is %FT%TZ", &utc_time);

  rexmpp_t s;
  rexmpp_err_t err;
  err = rexmpp_init(&s, jid, my_logger);
  if (err != REXMPP_SUCCESS) {
    puts("Failed to initialise rexmpp.");
    return -1;
  }
  if (tls_policy != NULL) {
    if (strcasecmp(tls_policy, "require") == 0) {
      s.tls_policy = REXMPP_TLS_REQUIRE;
    } else if (strcasecmp(tls_policy, "prefer") == 0) {
      s.tls_policy = REXMPP_TLS_PREFER;
    } else if (strcasecmp(tls_policy, "avoid") == 0) {
      s.tls_policy = REXMPP_TLS_AVOID;
    }
  }

  s.sasl_property_cb = my_sasl_property_cb;
  s.xml_in_cb = my_xml_in_cb;
  s.xml_out_cb = my_xml_out_cb;

  fd_set read_fds, write_fds;
  int nfds;
  struct timeval tv;
  struct timeval *mtv;
  int n = 0;

  do {
    err = rexmpp_run(&s, &read_fds, &write_fds);
    if (err == REXMPP_SUCCESS) {
      puts("done");
      break;
    }
    if (err != REXMPP_E_AGAIN) {
      printf("error: %s\n", rexmpp_strerror(err));
      break;
    }

    if (stage == TEST_CONNECTING && s.stream_state == REXMPP_STREAM_READY) {
      xmlNodePtr msg = rexmpp_xml_add_id(&s, xmlNewNode(NULL, "message"));
      xmlNewNs(msg, "jabber:client", NULL);
      xmlNewProp(msg, "to", jid);
      xmlNewProp(msg, "type", "chat");
      xmlNewTextChild(msg, NULL, "body", msg_text);
      rexmpp_send(&s, msg);
      stage = TEST_MESSAGE_SENT;
    } else if (stage == TEST_MESSAGE_RECEIVED) {
      rexmpp_stop(&s);
      stage = TEST_DONE;
    }

    time_t now = time(NULL);
    if (stage != TEST_DONE) {
      if (stage != TEST_TIMEOUT && difftime(now, t) > TIMEOUT) {
        puts("Timeout");
        rexmpp_stop(&s);
        stage = TEST_TIMEOUT;
      } else if (stage == TEST_TIMEOUT && difftime(now, t) > TIMEOUT + 10) {
        puts("Failed to close the stream properly, quitting");
        rexmpp_done(&s);
        return -1;
      }
    }

    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    nfds = rexmpp_fds(&s, &read_fds, &write_fds);
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    mtv = rexmpp_timeout(&s, (struct timeval*)&tv, (struct timeval*)&tv);

    n = select(nfds, &read_fds, &write_fds, NULL, mtv);
    if (n == -1) {
      printf("select error: %s\n", strerror(errno));
      break;
    }
    printf("stage = %u\n", stage);
  } while (1);

  rexmpp_done(&s);
  return (stage != TEST_DONE);
}
