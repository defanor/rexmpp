#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <gnutls/gnutls.h>

#include <rexmpp.h>


void my_logger (rexmpp_t *s, int priority, const char *fmt, va_list args) {
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
  fprintf(stderr, "[%s] ", priority_str);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
}

int my_sasl_property_cb (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop) {
  if (prop == GSASL_PASSWORD) {
    char buf[4096];
    printf("password: ");
    gets(buf);
    gsasl_property_set (sctx, GSASL_PASSWORD, buf);
    return GSASL_OK;
  }
  if (prop == GSASL_AUTHID) {
    gsasl_property_set (sctx, GSASL_AUTHID, "test");
    return GSASL_OK;
  }
  printf("unhandled gsasl property: %d\n", prop);
  return GSASL_NO_CALLBACK;
}

int my_xml_in_cb (rexmpp_t *s, xmlNodePtr node) {
  char *xml_buf = rexmpp_xml_serialize(node);
  printf("recv: %s\n", xml_buf);
  free(xml_buf);
  return 0;
}

int my_xml_out_cb (rexmpp_t *s, xmlNodePtr node) {
  char *xml_buf = rexmpp_xml_serialize(node);
  printf("send: %s\n", xml_buf);
  free(xml_buf);
  return 0;
}

main () {
  rexmpp_t s;
  rexmpp_err_t err;
  err = rexmpp_init(&s,
                    "test@foo.custom",
                    my_logger,
                    my_sasl_property_cb,
                    my_xml_in_cb,
                    my_xml_out_cb);
  if (err != REXMPP_SUCCESS) {
    puts("error");
    return -1;
  }
  /* gnutls_certificate_set_x509_key_file(s.gnutls_cred, */
  /*                                      "cert.pem", */
  /*                                      "key.pem", */
  /*                                      GNUTLS_X509_FMT_PEM); */
  fd_set read_fds, write_fds;
  int nfds;
  struct timeval tv;
  struct timeval *mtv;
  int n = 0;

  /* s.socks_host = "127.0.0.1"; */
  /* s.socks_port = 4321; */
  /* s.manual_host = "foo.custom"; */
  /* gnutls_certificate_set_x509_trust_file(s.gnutls_cred, */
  /*                                        "foo.custom.crt", */
  /*                                        GNUTLS_X509_FMT_PEM); */

  s.roster_cache_file = "roster.xml";

  do {

    if (n > 0 && FD_ISSET(STDIN_FILENO, &read_fds)) {
      char input[4096];
      ssize_t input_len;
      input_len = read(STDIN_FILENO, input, 4096);
      if (input_len == -1) {
        puts("input error");
      } else {
        input[input_len - 1] = '\0';
        if (strlen(input) != 0) {
          if (strcmp(input, ".") == 0) {
            rexmpp_stop(&s);
          } else if (strcmp(input, "connerr") == 0) {
            close(s.server_socket);
            s.server_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            gnutls_transport_set_int(s.gnutls_session, s.server_socket);
          } else {
            xmlNodePtr msg = rexmpp_xml_add_id(&s, xmlNewNode(NULL, "message"));
            xmlNewProp(msg, "to", "test2@foo.custom");
            xmlNewProp(msg, "type", "chat");
            xmlNewTextChild(msg, NULL, "body", input);
            rexmpp_send(&s, msg);
          }
        }
      }
    }
    err = rexmpp_run(&s, &read_fds, &write_fds);
    if (err == REXMPP_SUCCESS) {
      puts("done");
      break;
    }
    if (err != REXMPP_E_AGAIN) {
      puts("error");
      break;
    }
    /* printf("res %d / conn %d / tls %d / sasl %d / stream %d / carbons %d\n", */
    /*        s.resolver_state, */
    /*        s.tcp_state, */
    /*        s.tls_state, */
    /*        s.sasl_state, */
    /*        s.stream_state, */
    /*        s.carbons_state); */
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    nfds = rexmpp_fds(&s, &read_fds, &write_fds);
    mtv = rexmpp_timeout(&s, NULL, (struct timeval*)&tv);

    FD_SET(STDIN_FILENO, &read_fds);
    n = select(nfds, &read_fds, &write_fds, NULL, mtv);
    if (n == -1) {
      printf("select error: %s\n", strerror(errno));
      break;
    }
  } while (1);
  rexmpp_done(&s);
}
