/**
   @file basic.c
   @brief A reference rexmpp-based client.
   @author defanor <defanor@uberspace.net>
   @date 2020--2021
   @copyright MIT license.
*/

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <gsasl.h>
#include <time.h>
#include <stdlib.h>
#include <rexmpp.h>
#include <rexmpp_xml.h>
#include <rexmpp_sasl.h>
#include <rexmpp_base64.h>

int log_level = 8;

/* A logger callback. This one just prints all the logs into
   stderr. */
void my_logger (rexmpp_t *s, int priority, const char *fmt, va_list args) {
  if (priority >= log_level) {
    return;
  }
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
int my_sasl_property_cb (rexmpp_t *s, rexmpp_sasl_property prop) {
  if (prop == REXMPP_SASL_PROP_PASSWORD) {
    char *buf = NULL;
    size_t buf_len = 4096;
    printf("password: ");
    getline(&buf, &buf_len, stdin);
    if (buf != NULL) {
      if (buf[strlen(buf) - 1] == '\n') {
        buf[strlen(buf) - 1] = '\0';
      }
      rexmpp_sasl_property_set (s, REXMPP_SASL_PROP_PASSWORD, buf);
      free(buf);
    }
    return 0;
  }
  if (prop == REXMPP_SASL_PROP_AUTHID) {
    rexmpp_sasl_property_set (s, REXMPP_SASL_PROP_AUTHID, s->initial_jid.local);
    return 0;
  }
  /* GSASL fails on non-PLUS SCRAM mechanisms if
     REXMPP_TLS_CB_EXPORTER is provided, but asks for
     REXMPP_TLS_CB_EXPORTER when those are used anyway, so ensuring
     here that we only provide it for "-PLUS" mechanisms. */
  if (strstr(rexmpp_sasl_mechanism_name(s), "-PLUS") &&
      prop == REXMPP_SASL_PROP_CB_TLS_EXPORTER) {
    unsigned char cb_data[32];
    if (rexmpp_tls_get_channel_binding_data(s,
                                            s->tls,
                                            REXMPP_TLS_CB_EXPORTER,
                                            cb_data) == 0) {
      char *cb_data_base64 = NULL;
      size_t cb_size_base64 = 0;
      rexmpp_base64_to(cb_data, 32, &cb_data_base64, &cb_size_base64);
      rexmpp_sasl_property_set (s, REXMPP_SASL_PROP_CB_TLS_EXPORTER,
                                cb_data_base64);
      free(cb_data_base64);
      return 0;
    } else {
      return -1;
    }
  }
  printf("unhandled SASL property: %d\n", prop);
  return -1;
}

/* An XML in callback, printing what was received. */
int my_xml_in_cb (rexmpp_t *s, rexmpp_xml_t *node) {
  char *xml_buf = rexmpp_xml_serialize(node, 0);
  printf("recv: %s\n", xml_buf);
  free(xml_buf);
  return 0;
}

/* An XML out callback, printing what is about to be sent. */
int my_xml_out_cb (rexmpp_t *s, rexmpp_xml_t *node) {
  char *xml_buf = rexmpp_xml_serialize(node, 0);
  printf("send: %s\n", xml_buf);
  free(xml_buf);
  return 0;
}

int my_console_print_cb (rexmpp_t *s, const char *fmt, va_list args) {
  vprintf(fmt, args);
  return 0;
}

/* void my_socket_options(rexmpp_t *s, int sock) { */
/*   int pmtudisc = IP_PMTUDISC_WANT; */
/*   setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &pmtudisc, sizeof(pmtudisc)); */
/* } */

void print_help (char *prog_name) {
  printf("Usage: %s [options] <jid>\n" \
         "Options:\n" \
         "-c\tenable textual console\n" \
         "-x\tenable XML console\n" \
         "-l <n>\tset log level (0 to disable, 8 to print everything)\n"
         "-h\tprint this help message\n"
         , prog_name);
}

int main (int argc, char **argv) {
  int c, xml_console = 0, txt_console = 0, log = 0;
  if (argc < 2) {
    print_help(argv[0]);
    return -1;
  }
  while ((c = getopt (argc, argv, "xchl:")) != -1) {
    if (c == 'x') {
      xml_console = 1;
    } else if (c == 'c') {
      txt_console = 1;
    } else if (c == 'l') {
      log_level = atoi(optarg);
    } else if (c == 'h') {
      print_help(argv[0]);
      return 0;
    }
  }

  /* The minimal initialisation: provide an allocated rexmpp_t
     structure and an initial jid. */
  rexmpp_t s;
  rexmpp_err_t err;
  err = rexmpp_init(&s, argv[argc - 1], my_logger);
  if (err != REXMPP_SUCCESS) {
    puts("Failed to initialise rexmpp.");
    return -1;
  }

  /* Set the primary callback functions: for console, SASL, XML in and
     out. */
  if (txt_console) {
    s.console_print_cb = my_console_print_cb;
  }
  s.sasl_property_cb = my_sasl_property_cb;
  if (xml_console) {
    s.xml_in_cb = my_xml_in_cb;
    s.xml_out_cb = my_xml_out_cb;
  }

  /* Could set a client certificate for SASL EXTERNAL authentication
     and Jingle's DTLS here. */
  s.x509_key_file = "client.key";
  s.x509_cert_file = "client.crt";

  /* Could also set various other things manually. */
  /* s.socks_host = "127.0.0.1"; */
  /* s.socks_port = 4321; */
  /* s.manual_host = "localhost"; */
  s.local_address = "192.168.1.8";
  /* rexmpp_tls_set_x509_trust_file(&s, "localhost.crt"); */
  /* rexmpp_openpgp_set_home_dir(&s, "pgp"); */
  s.roster_cache_file = "roster.xml";
  /* s.tls_policy = REXMPP_TLS_AVOID; */
  /* s.socket_cb = my_socket_options; */

  /* Once the main structure is initialised and everything is
     sufficiently configured, we are ready to run the main loop and
     call rexmpp from it. */

  fd_set read_fds, write_fds;
  int nfds;
  struct timespec tv;
  struct timespec *mtv;
  struct timeval tv_ms;
  struct timeval *mtv_ms;
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
          if (input[0] == '<' && xml_console) {
            /* Raw XML input. */
            rexmpp_xml_t *node = rexmpp_xml_parse(input, input_len);
            if (node != NULL) {
              rexmpp_send(&s, node);
            } else {
              puts("Failed to parse XML");
            }
          } else if (txt_console) {
            rexmpp_console_feed(&s, input, input_len);
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
      printf("error: %s\n", rexmpp_strerror(err));
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
    mtv = rexmpp_timeout(&s, NULL, &tv);
    mtv_ms = NULL;
    if (mtv != NULL) {
      tv_ms.tv_sec = mtv->tv_sec;
      tv_ms.tv_usec = mtv->tv_nsec / 1000;
      mtv_ms = &tv_ms;
    }

    /* Add other file descriptors we are interested in, particularly
       stdin for user input. */
    FD_SET(STDIN_FILENO, &read_fds);

    /* Run select(2) with all those file descriptors and timeouts,
       waiting for either user input or some rexmpp event to occur. */
    n = select(nfds, &read_fds, &write_fds, NULL, mtv_ms);
    if (n == -1) {
      printf("select error: %s\n", strerror(errno));
      break;
    }
  } while (1);

  /* Deinitialise the rexmpp structure in the end, freeing whatever it
     allocated. */
  rexmpp_done(&s);
  return 0;
}
