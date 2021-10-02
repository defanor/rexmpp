/**
   @file rexmpp_jingle.c
   @brief Jingle routines
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.

The following XEPs are handled here so far:

- XEP-0166: Jingle
- XEP-0234: Jingle File Transfer
- XEP-0261: Jingle In-Band Bytestreams Transport Method
*/

#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <libgen.h>
#include <gsasl.h>
#include <gcrypt.h>

#include "rexmpp.h"
#include "rexmpp_jingle.h"


rexmpp_jingle_session_t *
rexmpp_jingle_session_by_id (rexmpp_t *s, const char *sid) {
  if (sid == NULL) {
    return NULL;
  }
  rexmpp_jingle_session_t *cur = s->jingle;
  while (cur != NULL) {
    if (strcmp(cur->sid, sid) == 0) {
      return cur;
    }
    cur = cur->next;
  }
  rexmpp_log(s, LOG_WARNING, "No Jingle session with sid %s found", sid);
  return NULL;
}

rexmpp_jingle_session_t *
rexmpp_jingle_session_by_ibb_sid (rexmpp_t *s, const char *ibb_sid) {
  if (ibb_sid == NULL) {
    return NULL;
  }
  rexmpp_jingle_session_t *cur = s->jingle;
  while (cur != NULL) {
    if (strcmp(cur->ibb_sid, ibb_sid) == 0) {
      return cur;
    }
    cur = cur->next;
  }
  rexmpp_log(s, LOG_WARNING,
             "No Jingle session with ibb_sid %s found", ibb_sid);
  return NULL;
}

void rexmpp_jingle_session_destroy (rexmpp_jingle_session_t *session) {
  if (session->jid != NULL) {
    free(session->jid);
  }
  if (session->sid != NULL) {
    free(session->sid);
  }
  if (session->negotiation != NULL) {
    xmlFreeNodeList(session->negotiation);
  }
  if (session->f != NULL) {
    fclose(session->f);
  }
  free(session);
}

void rexmpp_jingle_session_delete (rexmpp_t *s, rexmpp_jingle_session_t *sess) {
  if (sess == NULL) {
    return;
  }
  rexmpp_log(s, LOG_DEBUG, "Removing Jingle session %s", sess->sid);
  rexmpp_jingle_session_t **next_ptr = &(s->jingle), *cur = s->jingle;
  while (cur != NULL) {
    if (sess == cur) {
      *next_ptr = cur->next;
      rexmpp_jingle_session_destroy(sess);
    }
    next_ptr = &(cur->next);
    cur = cur->next;
  }
}

void rexmpp_jingle_stop (rexmpp_t *s) {
  while (s->jingle != NULL) {
    rexmpp_jingle_session_delete(s, s->jingle);
  }
}

int rexmpp_jingle_session_add (rexmpp_t *s, rexmpp_jingle_session_t *sess) {
  uint32_t sessions_num = 0;
  rexmpp_jingle_session_t *cur = s->jingle;
  while (cur != NULL) {
    sessions_num++;
    cur = cur->next;
  }
  if (sessions_num >= s->max_jingle_sessions) {
    rexmpp_log(s, LOG_ERR, "Too many Jingle sessions, discaring a new one");
    rexmpp_jingle_session_destroy(sess);
    return 0;
  }
  rexmpp_log(s, LOG_DEBUG, "Adding Jingle session %s", sess->sid);
  sess->next = s->jingle;
  s->jingle = sess;
  return 1;
}

void rexmpp_jingle_session_delete_by_id (rexmpp_t *s, const char *sid) {
  rexmpp_jingle_session_delete(s, rexmpp_jingle_session_by_id(s, sid));
}


void rexmpp_jingle_accept_file_cb (rexmpp_t *s,
                                   void *ptr,
                                   xmlNodePtr request,
                                   xmlNodePtr response,
                                   int success)
{
  (void)request;
  (void)response;
  char *sid = ptr;
  if (! success) {
    rexmpp_log(s, LOG_ERR, "Failed to accept a Jingle file transfer");
    rexmpp_jingle_session_delete_by_id(s, sid);
  }
  free(sid);
}

rexmpp_err_t
rexmpp_jingle_accept_file (rexmpp_t *s,
                           rexmpp_jingle_session_t *session,
                           const char *path)
{
  session->f = fopen(path, "wb");
  if (session->f == NULL) {
    rexmpp_log(s, LOG_ERR, "Failed to open %s for writing: %s",
               path, strerror(errno));
    return REXMPP_E_OTHER;
  }
  xmlNodePtr jingle = session->negotiation;
  xmlNodePtr content = rexmpp_xml_find_child(jingle, "urn:xmpp:jingle:1", "content");

  xmlNodePtr new_jingle = rexmpp_xml_new_node("jingle", "urn:xmpp:jingle:1");
  xmlNewProp(new_jingle, "action", "session-accept");
  xmlNewProp(new_jingle, "responder", s->assigned_jid.full);
  xmlNewProp(new_jingle, "sid", session->sid);
  xmlAddChild(new_jingle, xmlCopyNode(content, 1));
  xmlFreeNode(session->negotiation);
  session->negotiation = xmlCopyNode(new_jingle, 1);
  return rexmpp_iq_new(s, "set", session->jid, new_jingle,
                       rexmpp_jingle_accept_file_cb, strdup(session->sid));
}

rexmpp_err_t
rexmpp_jingle_accept_file_by_id (rexmpp_t *s,
                                 const char *sid,
                                 const char *path)
{
  return
    rexmpp_jingle_accept_file(s, rexmpp_jingle_session_by_id(s, sid), path);
}

void rexmpp_jingle_session_terminate_cb (rexmpp_t *s,
                                         void *ptr,
                                         xmlNodePtr request,
                                         xmlNodePtr response,
                                         int success)
{
  (void)request;
  (void)response;
  char *sid = ptr;
  if (! success) {
    rexmpp_log(s, LOG_ERR, "Failed to terminate session %s, removing anyway",
               sid);
  }
  rexmpp_jingle_session_delete_by_id(s, sid);
  free(sid);
}

rexmpp_err_t
rexmpp_jingle_session_terminate (rexmpp_t *s,
                                 const char *sid,
                                 xmlNodePtr reason_node,
                                 const char *reason_text)
{
  rexmpp_jingle_session_t *session = rexmpp_jingle_session_by_id(s, sid);
  if (session == NULL) {
    return REXMPP_E_OTHER;
  }
  xmlNodePtr jingle = rexmpp_xml_new_node("jingle", "urn:xmpp:jingle:1");
  xmlNewProp(jingle, "action", "session-terminate");
  xmlNewProp(jingle, "sid", sid);
  xmlNodePtr reason = rexmpp_xml_new_node("reason", "urn:xmpp:jingle:1");
  if (reason_text != NULL) {
    xmlNodePtr text = rexmpp_xml_new_node("text", "urn:xmpp:jingle:1");
    xmlNodeAddContent(text, reason_text);
    xmlAddChild(reason, text);
  }
  xmlAddChild(reason, reason_node);
  xmlAddChild(jingle, reason);
  return rexmpp_iq_new(s, "set", session->jid, jingle,
                       rexmpp_jingle_session_terminate_cb, strdup(sid));
}

rexmpp_err_t
rexmpp_jingle_accept_file_by_sid (rexmpp_t *s,
                                  const char *sid,
                                  const char *path)
{
  rexmpp_jingle_session_t *session = rexmpp_jingle_session_by_id(s, sid);
  if (session == NULL) {
    return REXMPP_E_OTHER;
  }
  return rexmpp_jingle_accept_file(s, session, path);
}

void rexmpp_jingle_send_file_cb (rexmpp_t *s,
                                 void *ptr,
                                 xmlNodePtr request,
                                 xmlNodePtr response,
                                 int success)
{
  (void)request;
  (void)response;
  char *sid = ptr;
  if (! success) {
    rexmpp_log(s, LOG_ERR, "Failed to initiate file sending for sid %s", sid);
    rexmpp_jingle_session_delete_by_id(s, sid);
  }
  free(sid);
}

rexmpp_err_t
rexmpp_jingle_send_file (rexmpp_t *s,
                         const char *jid,
                         char *path)
{
  FILE *fh = fopen(path, "rb");
  if (fh == NULL) {
    rexmpp_log(s, LOG_ERR, "Failed to open %s for reading", path);
    return REXMPP_E_OTHER;
  }
  char *sid = rexmpp_gen_id(s);
  char *ibb_sid = rexmpp_gen_id(s);

  xmlNodePtr jingle = rexmpp_xml_new_node("jingle", "urn:xmpp:jingle:1");
  xmlNewProp(jingle, "action", "session-initiate");
  xmlNewProp(jingle, "sid", sid);
  xmlNewProp(jingle, "initiator", s->assigned_jid.full);

  xmlNodePtr content = rexmpp_xml_new_node("content", "urn:xmpp:jingle:1");
  xmlNewProp(content, "creator", "initiator");
  xmlNewProp(content, "name", "IBB file");
  xmlAddChild(jingle, content);

  xmlNodePtr transport =
    rexmpp_xml_new_node("transport", "urn:xmpp:jingle:transports:ibb:1");
  xmlNewProp(transport, "block-size", "4096");
  xmlNewProp(transport, "sid", ibb_sid);
  xmlAddChild(content, transport);
  xmlNodePtr description =
    rexmpp_xml_new_node("description", "urn:xmpp:jingle:apps:file-transfer:5");
    xmlAddChild(content, description);
  xmlNodePtr file =
    rexmpp_xml_new_node("file", "urn:xmpp:jingle:apps:file-transfer:5");
  xmlAddChild(description, file);
  xmlNodePtr file_name =
    rexmpp_xml_new_node("name", "urn:xmpp:jingle:apps:file-transfer:5");
  xmlNodeAddContent(file_name, basename(path));
  xmlAddChild(file, file_name);

  char buf[4096];

  gcry_md_hd_t hd;
  /* todo: check for hashing errors */
  gcry_md_open(&hd, GCRY_MD_SHA256, 0);
  gcry_md_enable(hd, GCRY_MD_SHA3_256);
  size_t len = fread(buf, 1, 4096, fh);
  while (len > 0) {
    gcry_md_write(hd, buf, len);
    len = fread(buf, 1, 4096, fh);
  }
  gcry_md_final(hd);

  char *hash_base64 = NULL;
  size_t hash_base64_len = 0;
  gsasl_base64_to(gcry_md_read(hd, GCRY_MD_SHA256),
                  gcry_md_get_algo_dlen(GCRY_MD_SHA256),
                  &hash_base64,
                  &hash_base64_len);
  xmlNodePtr file_hash = rexmpp_xml_new_node("hash", "urn:xmpp:hashes:2");
  xmlNewProp(file_hash, "algo", "sha-256");
  xmlNodeAddContent(file_hash, hash_base64);
  free(hash_base64);
  xmlAddChild(file, file_hash);

  hash_base64 = NULL;
  hash_base64_len = 0;
  gsasl_base64_to(gcry_md_read(hd, GCRY_MD_SHA3_256),
                  gcry_md_get_algo_dlen(GCRY_MD_SHA3_256),
                  &hash_base64,
                  &hash_base64_len);
  file_hash = rexmpp_xml_new_node("hash", "urn:xmpp:hashes:2");
  xmlNewProp(file_hash, "algo", "sha3-256");
  xmlNodeAddContent(file_hash, hash_base64);
  free(hash_base64);
  xmlAddChild(file, file_hash);

  gcry_md_close(hd);

  long fsize = ftell(fh);
  fseek(fh, 0, SEEK_SET);
  snprintf(buf, 11, "%ld", fsize);
  xmlNodePtr file_size =
    rexmpp_xml_new_node("size", "urn:xmpp:jingle:apps:file-transfer:5");
  xmlNodeAddContent(file_size, buf);
  xmlAddChild(file, file_size);

  rexmpp_jingle_session_t *sess = malloc(sizeof(rexmpp_jingle_session_t));
  sess->jid = strdup(jid);
  sess->sid = sid;
  sess->ibb_sid = ibb_sid;
  sess->ibb_seq = 0;
  sess->negotiation = xmlCopyNode(jingle, 1);
  sess->f = fh;
  if (rexmpp_jingle_session_add(s, sess)) {
    return rexmpp_iq_new(s, "set", sess->jid, jingle,
                         rexmpp_jingle_send_file_cb, strdup(sess->sid));
  } else {
    return REXMPP_E_OTHER;
  }
}

void rexmpp_jingle_close_cb (rexmpp_t *s,
                             void *ptr,
                             xmlNodePtr request,
                             xmlNodePtr response,
                             int success)
{
  (void)request;
  (void)response;
  char *sid = ptr;
  if (success) {
    rexmpp_log(s, LOG_DEBUG, "Closed IBB stream for Jingle stream %s", sid);
  } else {
    rexmpp_log(s, LOG_ERR, "Failed to close IBB stream for Jingle stream %s", sid);
  }
  free(sid);
}

void rexmpp_jingle_send_cb (rexmpp_t *s,
                            void *ptr,
                            xmlNodePtr request,
                            xmlNodePtr response,
                            int success)
{
  (void)request;
  (void)response;
  char *sid = ptr;
  if (! success) {
    rexmpp_log(s, LOG_ERR, "An IBB stream error for Jingle sid %s", sid);
    rexmpp_jingle_session_delete_by_id(s, sid);
    free(sid);
    return;
  }
  rexmpp_jingle_session_t *session = rexmpp_jingle_session_by_id(s, sid);
  if (session == NULL) {
    rexmpp_log(s, LOG_ERR, "Jingle session %s doesn't exist", sid);
    free(sid);
    return;
  }
  if (feof(session->f)) {
    xmlNodePtr close = rexmpp_xml_new_node("close", "http://jabber.org/protocol/ibb");
    xmlNewProp(close, "sid", session->ibb_sid);
    rexmpp_iq_new(s, "set", session->jid, close,
                  rexmpp_jingle_close_cb, sid);
    return;
  } else {
    char buf[4096];
    size_t len = fread(buf, 1, 4096, session->f);
    if (len > 0) {
      xmlNodePtr data = rexmpp_xml_new_node("data", "http://jabber.org/protocol/ibb");
      xmlNewProp(data, "sid", session->ibb_sid);
      char *out = NULL;
      size_t out_len = 0;
      gsasl_base64_to(buf, len, &out, &out_len);
      xmlNodeAddContent(data, out);
      free(out);
      snprintf(buf, 11, "%u", session->ibb_seq);
      xmlNewProp(data, "seq", buf);
      session->ibb_seq++;
      rexmpp_iq_new(s, "set", session->jid, data,
                    rexmpp_jingle_send_cb, sid);
      return;
    } else {
      rexmpp_log(s, LOG_ERR, "Failed to read from a file: %s ", strerror(errno));
      rexmpp_jingle_session_terminate(s, sid,
                                      rexmpp_xml_new_node("media-error",
                                                          "urn:xmpp:jingle:1"),
                                      NULL);
    }
  }
  free(sid);
}

int rexmpp_jingle_iq (rexmpp_t *s, xmlNodePtr elem) {
  int handled = 0;
  if (! s->enable_jingle) {
    return handled;
  }
  xmlNodePtr jingle = rexmpp_xml_find_child(elem, "urn:xmpp:jingle:1", "jingle");
  if (jingle != NULL) {
    handled = 1;
    char *action = xmlGetProp(jingle, "action");
    char *sid = xmlGetProp(jingle, "sid");
    char *from_jid = xmlGetProp(elem, "from");
    if (action != NULL && sid != NULL && from_jid != NULL) {
      if (strcmp(action, "session-initiate") == 0) {
        /* todo: could be more than one content element, handle that */
        xmlNodePtr content = rexmpp_xml_find_child(jingle, "urn:xmpp:jingle:1", "content");
        if (content == NULL) {
          rexmpp_iq_reply(s, elem, "error", rexmpp_xml_error("cancel", "bad-request"));
        } else {
          rexmpp_iq_reply(s, elem, "result", NULL);

          xmlNodePtr description =
            rexmpp_xml_find_child(content, "urn:xmpp:jingle:apps:file-transfer:5",
                                  "description");
          xmlNodePtr transport =
            rexmpp_xml_find_child(content, "urn:xmpp:jingle:transports:ibb:1",
                                  "transport");
          if (description == NULL) {
            rexmpp_jingle_session_terminate(s, sid,
                                            rexmpp_xml_new_node("unsupported-applications",
                                                                "urn:xmpp:jingle:1"),
                                            NULL);
          } else if (transport == NULL) {
            rexmpp_jingle_session_terminate(s, sid,
                                            rexmpp_xml_new_node("unsupported-transports",
                                                                "urn:xmpp:jingle:1"),
                                            NULL);
          } else {
            char *ibb_sid = xmlGetProp(transport, "sid");
            if (ibb_sid != NULL) {
              rexmpp_jingle_session_t *sess = malloc(sizeof(rexmpp_jingle_session_t));
              sess->jid = strdup(from_jid);
              sess->sid = strdup(sid);
              sess->ibb_sid = ibb_sid;
              sess->ibb_seq = 0;
              sess->negotiation = xmlCopyNode(jingle, 1);
              sess->f = NULL;
              rexmpp_log(s, LOG_DEBUG, "Jingle session-initiate from %s, sid %s",
                         sess->jid, sid);
              rexmpp_jingle_session_add(s, sess);
            } else {
              rexmpp_log(s, LOG_ERR, "Jingle IBB transport doesn't have a sid attribute");
              rexmpp_jingle_session_terminate(s, sid,
                                              rexmpp_xml_new_node("unsupported-transports",
                                                                  "urn:xmpp:jingle:1"),
                                              NULL);
            }
          }
        }
      } else if (strcmp(action, "session-terminate") == 0) {
        /* todo: check/log the reason */
        rexmpp_jingle_session_delete_by_id(s, sid);
        rexmpp_iq_reply(s, elem, "result", NULL);
      } else if (strcmp(action, "session-accept") == 0) {
        rexmpp_iq_reply(s, elem, "result", NULL);
        rexmpp_jingle_session_t *session = rexmpp_jingle_session_by_id(s, sid);
        if (session != NULL) {
          xmlNodePtr open = rexmpp_xml_new_node("open", "http://jabber.org/protocol/ibb");
          xmlNewProp(open, "sid", session->ibb_sid);
          xmlNewProp(open, "block-size", "4096");
          xmlNewProp(open, "stanza", "iq");
          rexmpp_iq_new(s, "set", session->jid, open,
                        rexmpp_jingle_send_cb, strdup(sid));
        }
      } else {
        rexmpp_log(s, LOG_WARNING, "Unknown Jingle action: %s", action);
        rexmpp_iq_reply(s, elem, "error", rexmpp_xml_error("cancel", "bad-request"));
      }
    } else {
      rexmpp_log(s, LOG_WARNING, "Received a malformed Jingle element");
      rexmpp_iq_reply(s, elem, "error", rexmpp_xml_error("cancel", "bad-request"));
    }
    if (action != NULL) {
      free(action);
    }
    if (sid != NULL) {
      free(sid);
    }
    if (from_jid != NULL) {
      free(from_jid);
    }
  }

  /* XEP-0261: Jingle In-Band Bytestreams Transport Method */
  xmlNodePtr ibb_open = rexmpp_xml_find_child(elem, "http://jabber.org/protocol/ibb", "open");
  if (ibb_open != NULL) {
    handled = 1;
    /* no-op, though could check sid here. */
    rexmpp_iq_reply(s, elem, "result", NULL);
  }
  xmlNodePtr ibb_close = rexmpp_xml_find_child(elem, "http://jabber.org/protocol/ibb", "close");
  if (ibb_close != NULL) {
    handled = 1;
    rexmpp_iq_reply(s, elem, "result", NULL);
    char *sid = xmlGetProp(ibb_close, "sid");
    
    if (sid != NULL) {
      rexmpp_jingle_session_t *session = rexmpp_jingle_session_by_ibb_sid(s, sid);
      if (session != NULL) {
        rexmpp_jingle_session_terminate
          (s, session->sid,
           rexmpp_xml_new_node("success", "urn:xmpp:jingle:1"), NULL);
      }
      free(sid);
    }
  }
  xmlNodePtr ibb_data = rexmpp_xml_find_child(elem, "http://jabber.org/protocol/ibb", "data");
  if (ibb_data != NULL) {
    handled = 1;
    char *sid = xmlGetProp(ibb_data, "sid");
    if (sid != NULL) {
      rexmpp_jingle_session_t *session = rexmpp_jingle_session_by_ibb_sid(s, sid);
      if (session != NULL && session->f != NULL) {
        char *data = NULL, *data_base64 = xmlNodeGetContent(ibb_data);
        if (data_base64 != NULL) {
          size_t data_len = 0;
          int sasl_err = gsasl_base64_from(data_base64, strlen(data_base64),
                                           &data, &data_len);
          free(data_base64);
          if (sasl_err != GSASL_OK) {
            rexmpp_log(s, LOG_ERR, "Base-64 decoding failure: %s",
                       gsasl_strerror(sasl_err));
          } else {
            size_t written = fwrite(data, 1, data_len, session->f);
            if (written != data_len) {
              rexmpp_log(s, LOG_ERR, "Wrote %d bytes, expected %d", written, data_len);
              /* todo: maybe introduce buffering, or make it an error */
            }
          }
        }
      }
      free(sid);
    }
    /* todo: report errors */
    rexmpp_iq_reply(s, elem, "result", NULL);
  }
  return handled;
}
