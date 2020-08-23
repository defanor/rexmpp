#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <gnutls/gnutls.h>
#include <gsasl.h>
#include <rexmpp.h>

/* A logger callback. This one just prints all the logs into
   stderr. */
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

/* A SASL property callback, used to retrieve credentials. This one
   just asks user for a password and provides AUTHID based on the
   initial JID. */
int my_sasl_property_cb (rexmpp_t *s, Gsasl_property prop) {
  if (prop == GSASL_PASSWORD) {
    char buf[4096];
    printf("password: ");
    gets(buf);
    gsasl_property_set (s->sasl_session, GSASL_PASSWORD, buf);
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
  printf("unhandled gsasl property: %d\n", prop);
  return GSASL_NO_CALLBACK;
}

/* An XML in callback, printing what was received. */
int my_xml_in_cb (rexmpp_t *s, xmlNodePtr node) {
  char *xml_buf = rexmpp_xml_serialize(node);
  printf("recv: %s\n", xml_buf);
  free(xml_buf);
  return 0;
}

/* An XML out callback, printing what is about to be sent. */
int my_xml_out_cb (rexmpp_t *s, xmlNodePtr node) {
  char *xml_buf = rexmpp_xml_serialize(node);
  printf("send: %s\n", xml_buf);
  free(xml_buf);
  return 0;
}

main (int argc, char **argv) {
  if (argc != 2) {
    printf("Usage: %s <jid>", argv[0]);
    return -1;
  }

  /* The minimal initialisation: provide an allocated rexmpp_t
     structure and an initial jid. */
  rexmpp_t s;
  rexmpp_err_t err;
  err = rexmpp_init(&s, argv[1]);
  if (err != REXMPP_SUCCESS) {
    puts("Failed to initialise rexmpp.");
    return -1;
  }

  /* Set the primary callback functions: for logging, SASL, XML in and
     out. */
  s.log_function = my_logger;
  s.sasl_property_cb = my_sasl_property_cb;
  s.xml_in_cb = my_xml_in_cb;
  s.xml_out_cb = my_xml_out_cb;

  /* Could set a client certificate for SASL EXTERNAL authentication
     here. */
  /* gnutls_certificate_set_x509_key_file(s.gnutls_cred, */
  /*                                      "cert.pem", */
  /*                                      "key.pem", */
  /*                                      GNUTLS_X509_FMT_PEM); */

  /* Could also set various other things manually. */
  /* s.socks_host = "127.0.0.1"; */
  /* s.socks_port = 4321; */
  /* s.manual_host = "foo.custom"; */
  /* gnutls_certificate_set_x509_trust_file(s.gnutls_cred, */
  /*                                        "foo.custom.crt", */
  /*                                        GNUTLS_X509_FMT_PEM); */
  s.roster_cache_file = "roster.xml";

  /* Once the main structure is initialised and everything is
     sufficiently configured, we are ready to run the main loop and
     call rexmpp from it. */

  fd_set read_fds, write_fds;
  int nfds;
  struct timeval tv;
  struct timeval *mtv;
  int n = 0;

  do {

    /* Check if we have some user input. */
    if (n > 0 && FD_ISSET(STDIN_FILENO, &read_fds)) {
      char input[4097];
      ssize_t input_len;
      input_len = read(STDIN_FILENO, input, 4096);
      if (input_len == -1) {
        puts("input error");
      } else {
        input[input_len - 1] = '\0';
        if (strlen(input) != 0) {
          if (input[0] == '<') {
            /* Raw XML input. */
            xmlDocPtr doc = xmlReadMemory(input, input_len, "", "utf-8", 0);
            if (doc != NULL) {
              xmlNodePtr node = xmlDocGetRootElement(doc);
              if (node != NULL) {
                xmlUnlinkNode(node);
                rexmpp_send(&s, node);
              } else {
                puts("No root node");
              }
              xmlFreeDoc(doc);
            } else {
              puts("Failed to read a document");
            }
          } else if (strcmp(input, ".") == 0) {
            /* Exit. */
            rexmpp_stop(&s);
          } else {
            /* A test message for a fixed JID. */
            xmlNodePtr msg = rexmpp_xml_add_id(&s, xmlNewNode(NULL, "message"));
            xmlNewProp(msg, "to", "test2@foo.custom");
            xmlNewProp(msg, "type", "chat");
            xmlNewTextChild(msg, NULL, "body", input);
            rexmpp_send(&s, msg);
          }
        }
      }
    }

    /* Run a single rexmpp iteration. */
    err = rexmpp_run(&s, &read_fds, &write_fds);
    if (err == REXMPP_SUCCESS) {
      puts("done");
      break;
    }
    if (err != REXMPP_E_AGAIN) {
      puts("error");
      break;
    }
    /* Could inspect the state here. */
    /* printf("res %d / conn %d / tls %d / sasl %d / stream %d / carbons %d\n", */
    /*        s.resolver_state, */
    /*        s.tcp_state, */
    /*        s.tls_state, */
    /*        s.sasl_state, */
    /*        s.stream_state, */
    /*        s.carbons_state); */

    /* Ask rexmpp which file descriptors it is interested in, and what
       the timeouts should be. */
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    nfds = rexmpp_fds(&s, &read_fds, &write_fds);
    mtv = rexmpp_timeout(&s, NULL, (struct timeval*)&tv);

    /* Add other file descriptors we are interested in, particularly
       stdin for user input. */
    FD_SET(STDIN_FILENO, &read_fds);

    /* Run select(2) with all those file descriptors and timeouts,
       waiting for either user input or some rexmpp event to occur. */
    n = select(nfds, &read_fds, &write_fds, NULL, mtv);
    if (n == -1) {
      printf("select error: %s\n", strerror(errno));
      break;
    }
  } while (1);

  /* Deinitialise the rexmpp structure in the end, freeing whatever it
     allocated. */
  rexmpp_done(&s);
}
