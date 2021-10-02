/**
   @file xml-interface.c
   @brief An XML interface to communicate with Emacs.
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.

A basic and ad hoc XML interface. The parent process (e.g., Emacs) is
supposed to respond to requests starting with the most recent one.

This program's output is separated with NUL ('\0') characters, to
simplify parsing in Emacs, while the input is separated with newline
and EOF ones, to simplify reading with libxml2.

*/

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <gnutls/gnutls.h>
#include <rexmpp.h>
#include <rexmpp_openpgp.h>


void print_xml (xmlNodePtr node) {
  char *s = rexmpp_xml_serialize(node);
  printf("%s%c\n", s, '\0');
  free(s);
}

xmlNodePtr read_xml () {
  xmlNodePtr elem = NULL;
  xmlDocPtr doc = xmlReadFd(STDIN_FILENO, "", "utf-8", 0);
  if (doc != NULL) {
    elem = xmlCopyNode(xmlDocGetRootElement(doc), 1);
    xmlFreeDoc(doc);
    return elem;
  }
  return NULL;
}


char *request (rexmpp_t *s, xmlNodePtr payload)
{
  xmlNodePtr req = rexmpp_xml_add_id(s, xmlNewNode(NULL, "request"));
  xmlAddChild(req, payload);
  print_xml(req);
  char *id = xmlGetProp(req, "id");
  xmlFreeNode(req);
  return id;
}

xmlNodePtr read_response (rexmpp_t *s, const char *id) {
  xmlNodePtr elem = read_xml();
  if (elem != NULL) {
    if (rexmpp_xml_match(elem, NULL, "response")) {
      char *resp_id = xmlGetProp(elem, "id");
      if (resp_id != NULL) {
        int matches = (strcmp(resp_id, id) == 0);
        free(resp_id);
        if (matches) {
          return elem;
        } else {
          /* Just fail for now, to avoid deadlocks. Though this
             shouldn't happen. */
          xmlFreeNode(elem);
          rexmpp_log(s, LOG_ERR, "Unexpected response ID received.");
          return NULL;
        }
      }
    }
    req_process(s, elem);
    xmlFreeNode(elem);
  }
  return read_response(s, id);
}

xmlNodePtr req_block (rexmpp_t *s, xmlNodePtr req) {
  char *id = request(s, req);
  xmlNodePtr resp = read_response(s, id);
  free(id);
  return resp;
}

void respond_xml (rexmpp_t *s,
                  const char *id,
                  xmlNodePtr payload) {
  xmlNodePtr response = xmlNewNode(NULL, "response");
  xmlNewProp(response, "id", id);
  if (payload != NULL) {
    xmlAddChild(response, payload);
  }
  print_xml(response);
  xmlFreeNode(response);
}

void respond_text (rexmpp_t *s,
                   const char *id,
                   const char *buf) {
  xmlNodePtr response = xmlNewNode(NULL, "response");
  xmlNewProp(response, "id", id);
  if (buf != NULL) {
    xmlNodeAddContent(response, buf);
  }
  print_xml(response);
  xmlFreeNode(response);
}

void on_http_upload (rexmpp_t *s, void *cb_data, const char *url) {
  char *id = cb_data;
  respond_text(s, id, url);
  free(id);
}

void req_process (rexmpp_t *s,
                  xmlNodePtr elem)
{
  char *id = xmlGetProp(elem, "id");
  if (id == NULL) {
    return;
  }
  rexmpp_err_t err;
  char buf[64];
  xmlNodePtr child = xmlFirstElementChild(elem);
  if (rexmpp_xml_match(child, NULL, "stop")) {
    snprintf(buf, 64, "%d", rexmpp_stop(s));
    respond_text(s, id, buf);
  } else if (rexmpp_xml_match(child, NULL, "console")) {
    char *in = xmlNodeGetContent(child);
    rexmpp_console_feed(s, in, strlen(in));
    free(in);
    respond_text(s, id, NULL);
  } else if (rexmpp_xml_match(child, NULL, "send")) {
    if (xmlFirstElementChild(child)) {
      xmlNodePtr stanza = xmlCopyNode(xmlFirstElementChild(child), 1);
      snprintf(buf, 64, "%d", rexmpp_send(s, stanza));
      respond_text(s, id, buf);
    }
  } else if (rexmpp_xml_match(child, NULL, "openpgp-decrypt-message")) {
    int valid;
    xmlNodePtr plaintext =
      rexmpp_openpgp_decrypt_verify_message(s, xmlFirstElementChild(child),
                                            &valid);
    /* todo: wrap into another element, with the 'valid' attribute */
    respond_xml(s, id, plaintext);
  } else if (rexmpp_xml_match(child, NULL, "openpgp-payload")) {
    enum rexmpp_ox_mode mode = REXMPP_OX_CRYPT;
    char *mode_str = xmlGetProp(child, "mode");
    if (strcmp(mode_str, "sign") == 0) {
      mode = REXMPP_OX_SIGN;
    } else if (strcmp(mode_str, "signcrypt") == 0) {
      mode = REXMPP_OX_SIGNCRYPT;
    }
    free(mode_str);

    xmlNodePtr payload_xml =
      xmlFirstElementChild(rexmpp_xml_find_child(child, NULL, "payload"));

    char **recipients[16];
    int recipients_num = 0;
    xmlNodePtr plchild;
    for (plchild = xmlFirstElementChild(child);
         plchild != NULL && recipients_num < 15;
         plchild = plchild->next) {
      if (rexmpp_xml_match(plchild, NULL, "to")) {
        recipients[recipients_num] = xmlNodeGetContent(plchild);
        recipients_num++;
      }
    }
    recipients[recipients_num] = NULL;
    char *payload_str =
      rexmpp_openpgp_payload(s, xmlCopyNode(payload_xml, 1), recipients, NULL, mode);
    for (recipients_num = 0; recipients[recipients_num] != NULL; recipients_num++) {
      free(recipients[recipients_num]);
    }
    respond_text(s, id, payload_str);
    free(payload_str);
  } else if (rexmpp_xml_match(child, NULL, "get-name")) {
    char *jid = xmlNodeGetContent(child);
    if (jid != NULL) {
      char *name = rexmpp_get_name(s, jid);
      if (name != NULL) {
        respond_text(s, id, name);
        free(name);
      }
      free(jid);
    }
  } else if (rexmpp_xml_match(child, NULL, "http-upload")) {
    char *in = xmlNodeGetContent(child);
    rexmpp_http_upload_path(s, NULL, in, NULL, on_http_upload, strdup(id));
    free(in);
  }
  free(id);
  return;
}

void my_logger (rexmpp_t *s, int priority, const char *fmt, va_list args) {
  /* Or could just use stderr. */
  char *buf = malloc(4096);
  vsnprintf(buf, 4096, fmt, args);
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
  xmlNodePtr node = xmlNewNode(NULL, "log");
  xmlNewProp(node, "priority", priority_str);
  xmlNodeAddContent(node, buf);
  free(buf);
  print_xml(node);
  xmlFreeNode(node);
}

void my_console_print_cb (rexmpp_t *s, const char *fmt, va_list args) {
  char *buf = malloc(1024 * 20);
  vsnprintf(buf, 1024 * 20, fmt, args);
  xmlNodePtr node = xmlNewNode(NULL, "console");
  xmlNodeAddContent(node, buf);
  free(buf);
  print_xml(node);
  xmlFreeNode(node);
}

int my_sasl_property_cb (rexmpp_t *s, rexmpp_sasl_property prop) {
  if (prop == REXMPP_SASL_PROP_AUTHID) {
    rexmpp_sasl_property_set (s, REXMPP_SASL_PROP_AUTHID, s->initial_jid.local);
    return 0;
  }
  char *prop_str = NULL;
  switch (prop) {
  case REXMPP_SASL_PROP_PASSWORD: prop_str = "password"; break;
  case REXMPP_SASL_PROP_AUTHID: prop_str = "authid"; break;
  default: return -1;
  }
  xmlNodePtr req = xmlNewNode(NULL, "sasl");
  xmlNewProp(req, "property", prop_str);
  xmlNodePtr rep = req_block(s, req);
  if (rep == NULL) {
    return -1;
  }
  char *val = xmlNodeGetContent(rep);
  xmlFreeNode(rep);
  if (val == NULL) {
    return -1;
  }
  rexmpp_sasl_property_set (s, prop, val);
  free(val);
  return GSASL_OK;
}

int my_xml_in_cb (rexmpp_t *s, xmlNodePtr node) {
  xmlNodePtr req = xmlNewNode(NULL, "xml-in");
  xmlAddChild(req, xmlCopyNode(node, 1));
  xmlNodePtr rep = req_block(s, req);
  if (rep == NULL) {
    return 0;
  }
  char *val = xmlNodeGetContent(rep);
  xmlFreeNode(rep);
  if (val == NULL) {
    return 0;
  }
  int n = atoi(val);
  free(val);
  return n;
}

int my_xml_out_cb (rexmpp_t *s, xmlNodePtr node) {
  xmlNodePtr req = xmlNewNode(NULL, "xml-out");
  xmlAddChild(req, xmlCopyNode(node, 1));
  xmlNodePtr rep = req_block(s, req);
  if (rep == NULL) {
    return 0;
  }
  char *val = xmlNodeGetContent(rep);
  xmlFreeNode(rep);
  if (val == NULL) {
    return 0;
  }
  int n = atoi(val);
  free(val);
  return n;
}


int main (int argc, char **argv) {

  /* The minimal initialisation: provide an allocated rexmpp_t
     structure and an initial jid. */
  rexmpp_t s;
  rexmpp_err_t err;
  err = rexmpp_init(&s, argv[1], my_logger);
  if (err != REXMPP_SUCCESS) {
    return -1;
  }
  s.sasl_property_cb = my_sasl_property_cb;
  s.xml_in_cb = my_xml_in_cb;
  s.xml_out_cb = my_xml_out_cb;
  s.console_print_cb = my_console_print_cb;

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
  /* rexmpp_openpgp_set_home_dir(&s, "pgp"); */
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
      xmlNodePtr elem = read_xml();
      if (elem != NULL) {
        req_process(&s, elem);
        xmlFreeNode(elem);
      }
    }

    /* Run a single rexmpp iteration. */
    err = rexmpp_run(&s, &read_fds, &write_fds);

    if (err == REXMPP_SUCCESS) {
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
  return 0;
}
