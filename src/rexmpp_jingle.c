/**
   @file rexmpp_jingle.c
   @brief Jingle routines
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.

The following XEPs are handled here so far:

- XEP-0166: Jingle

File transfer over IBB:

- XEP-0234: Jingle File Transfer
- XEP-0261: Jingle In-Band Bytestreams Transport Method

A/V calls over ICE-UDP + DTLS-SRTP:

- XEP-0167: Jingle RTP Sessions
- XEP-0176: Jingle ICE-UDP Transport Method
- XEP-0320: Use of DTLS-SRTP in Jingle Sessions
- XEP-0215: External Service Discovery

*/

#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <libgen.h>
#include <gcrypt.h>

#include "config.h"

#ifdef ENABLE_CALLS
#include <inttypes.h>
#include <glib.h>
#include <gio/gnetworking.h>
#include <nice.h>
#include <agent.h>
#include <srtp2/srtp.h>
#include <math.h>
#include "portaudio.h"
#ifdef HAVE_OPUS
#include <opus.h>
#endif
#endif

#include "rexmpp.h"
#include "rexmpp_xml.h"
#include "rexmpp_jingle.h"
#include "rexmpp_base64.h"
#include "rexmpp_random.h"
#include "rexmpp_tls.h"


/* https://en.wikipedia.org/wiki/G.711 */
uint8_t rexmpp_pcma_encode (int16_t x) {
  uint8_t sign = 0x80;
  uint8_t pos;
  uint8_t val = 0;
  if (x < 0) {
    x = -x;
    sign = 0;
  }
  x >>= 3;
  for (pos = 11; pos > 5 && ! (x & (1 << pos)); pos--);
  val = (x >> (pos - 4)) & 0xf;
  return (sign | ((pos - 4) << 4) | val) ^ 0x55;
}

int16_t rexmpp_pcma_decode (uint8_t x) {
  x ^= 0x55;
  int16_t sign = -1;
  uint8_t shift = (x >> 4) & 7;
  int16_t val = x & 0xf;
  if (x & 0x80) {
    x ^= 0x80;
    sign = 1;
  }
  val = (val << 1) | 1;
  if (shift > 0) {
    val = (val | 0x20) << (shift - 1);
  }
  val <<= 3;
  return sign * val;
}

uint8_t rexmpp_pcmu_encode (int16_t x) {
  uint8_t sign = 0;
  uint8_t pos;
  uint8_t val = 0;
  if (x < 0) {
    x = -x;
    sign = 0x80;
  }
  x >>= 2;
  for (pos = 12; pos > 5 && ! (x & (1 << pos)); pos--);
  val = (x >> (pos - 4)) & 0xf;
  return (sign | ((pos - 4) << 4) | val) ^ 0xff;
}

int16_t rexmpp_pcmu_decode (uint8_t x) {
  x ^= 0xff;
  int16_t sign = 1;
  uint8_t shift = (x >> 4) & 7;
  int16_t val = x & 0xf;
  if (x & 0x80) {
    x ^= 0x80;
    sign = -1;
  }
  val = (val << 1) | 1;
  if (shift > 0) {
    val = (val | 0x20) << (shift - 1);
  }
  val <<= 2;
  return sign * val;
}

rexmpp_xml_t *
rexmpp_jingle_session_payload_by_id (rexmpp_jingle_session_t *sess,
                                     int payload_type_id)
{
  if (sess->accept == NULL) {
    return NULL;
  }
  rexmpp_xml_t *descr_child =
    rexmpp_xml_first_elem_child
    (rexmpp_xml_find_child
     (rexmpp_xml_find_child
      (sess->accept, "urn:xmpp:jingle:1", "content"),
      "urn:xmpp:jingle:apps:rtp:1", "description"));
  while (descr_child != NULL) {
    if (rexmpp_xml_match(descr_child, "urn:xmpp:jingle:apps:rtp:1",
                         "payload-type"))
      {
        const char *pl_id = rexmpp_xml_find_attr_val(descr_child, "id");
        if (pl_id != NULL && atoi(pl_id) == payload_type_id) {
          return descr_child;
        }
      }
    descr_child = rexmpp_xml_next_elem_sibling(descr_child);
  }
  return NULL;
}

#ifdef ENABLE_CALLS
int rexmpp_jingle_session_configure_audio (rexmpp_jingle_session_t *sess) {
  if (sess->accept == NULL) {
    return 0;
  }
  rexmpp_xml_t *descr_child =
    rexmpp_xml_first_elem_child
    (rexmpp_xml_find_child
     (rexmpp_xml_find_child(sess->accept, "urn:xmpp:jingle:1", "content"),
      "urn:xmpp:jingle:apps:rtp:1", "description"));
  while (descr_child != NULL) {
    if (rexmpp_xml_match(descr_child, "urn:xmpp:jingle:apps:rtp:1",
                         "payload-type"))
      {
        const char *pl_id = rexmpp_xml_find_attr_val(descr_child, "id");
        if (pl_id != NULL) {
          if (atoi(pl_id) == 0) {
            rexmpp_log(sess->s, LOG_INFO,
                       "Setting the codec to PCMU (0) for Jingle session %s",
                       sess->sid);
            sess->codec = REXMPP_CODEC_PCMU;
            sess->payload_type = 0;
            return sess->payload_type;
          }
          if (atoi(pl_id) == 8) {
            rexmpp_log(sess->s, LOG_INFO,
                       "Setting the codec to PCMA (8) for Jingle session %s",
                       sess->sid);
            sess->codec = REXMPP_CODEC_PCMA;
            sess->payload_type = 8;
            return sess->payload_type;
          }
#ifdef HAVE_OPUS
          const char *pl_name = rexmpp_xml_find_attr_val(descr_child, "name");
          if ((pl_name != NULL) && (strcmp(pl_name, "opus") == 0)) {
            sess->codec = REXMPP_CODEC_OPUS;
            sess->payload_type = atoi(pl_id);
            rexmpp_log(sess->s, LOG_INFO,
                       "Setting the codec to Opus (%u) for Jingle session %s",
                       sess->payload_type, sess->sid);
            return sess->payload_type;
          }
#endif  /* HAVE_OPUS */
        }
      }
    descr_child = rexmpp_xml_next_elem_sibling(descr_child);
  }
  return 0;
}


static int rexmpp_pa_callback (const void *input,
                               void *output,
                               unsigned long frameCount,
                               const PaStreamCallbackTimeInfo* timeInfo,
                               PaStreamCallbackFlags statusFlags,
                               void *userData)
{
  (void)timeInfo;
  (void)statusFlags;
  struct pa_buffers *data = (struct pa_buffers*)userData;
  int16_t *out = (int16_t*)output;
  int16_t *in = (int16_t*)input;
  unsigned int i;
  for (i = 0; i < frameCount; i++) {
    if (in != NULL) {
      data->capture.buf[data->capture.write_pos] = in[i];
      data->capture.write_pos++;
      data->capture.write_pos %= PA_BUF_SIZE;
    }

    if (data->playback.read_pos != data->playback.write_pos) {
      out[i] = data->playback.buf[data->playback.read_pos];
      data->playback.read_pos++;
      data->playback.read_pos %= PA_BUF_SIZE;
    } else {
      out[i] = 0;
    }
  }
  return 0;
}

void
rexmpp_jingle_run_audio (rexmpp_jingle_session_t *sess) {
  rexmpp_random_buf(&(sess->rtp_seq_num), sizeof(uint16_t));
  sess->rtp_last_seq_num = 0xffff;
  rexmpp_random_buf(&(sess->rtp_timestamp), sizeof(uint32_t));
  rexmpp_random_buf(&(sess->rtp_ssrc), sizeof(uint32_t));

  int rate = 8000;
  int channels = 1;
#ifdef HAVE_OPUS
  if (sess->codec == REXMPP_CODEC_OPUS) {
    rate = 48000;
    channels = 2;
    int opus_error;
    sess->opus_enc =
      opus_encoder_create(rate, channels, OPUS_APPLICATION_VOIP, &opus_error);
    sess->opus_dec =
      opus_decoder_create(rate, channels, &opus_error);
  }
#endif  /* HAVE_OPUS */

  rexmpp_log(sess->s, LOG_DEBUG,
             "Setting up an audio stream: SSRC %" PRIx32
             ", %d Hz, %d channels",
             sess->rtp_ssrc, rate, channels);

  PaError err = Pa_OpenDefaultStream (&(sess->pa_stream),
                                      channels,
                                      channels,
                                      paInt16,
                                      /* paFloat32, */
                                      rate,
                                      /* 480, */
                                      paFramesPerBufferUnspecified,
                                      rexmpp_pa_callback,
                                      &(sess->ring_buffers));
  if (err != paNoError) {
    rexmpp_log(sess->s, LOG_ERR, "Failed to open a PA stream: %s",
               Pa_GetErrorText(err));
  }
  err = Pa_StartStream(sess->pa_stream);
  if (err != paNoError) {
    rexmpp_log(sess->s, LOG_ERR, "Failed to start a PA stream: %s",
               Pa_GetErrorText(err));
  }
}
#endif  /* ENABLE_CALLS */


rexmpp_jingle_session_t *
rexmpp_jingle_session_by_id (rexmpp_t *s, const char *sid) {
  if (sid == NULL) {
    return NULL;
  }
  rexmpp_jingle_session_t *cur = s->jingle->sessions;
  while (cur != NULL) {
    if (strcmp(cur->sid, sid) == 0) {
      return cur;
    }
    cur = cur->next;
  }
  rexmpp_log(s, LOG_WARNING, "No Jingle session with sid %s found", sid);
  return NULL;
}

void rexmpp_jingle_session_destroy (rexmpp_jingle_session_t *session) {
  if (session->jid != NULL) {
    free(session->jid);
  }
  if (session->sid != NULL) {
    free(session->sid);
  }
  if (session->initiate != NULL) {
    rexmpp_xml_free_list(session->initiate);
  }
  if (session->accept != NULL) {
    rexmpp_xml_free_list(session->accept);
  }
  if (session->ibb_fh != NULL) {
    fclose(session->ibb_fh);
  }
#ifdef ENABLE_CALLS
  if (session->type == REXMPP_JINGLE_SESSION_MEDIA) {
    int i;
    if (session->pa_stream != NULL) {
      PaError err = Pa_StopStream(session->pa_stream);
      if (err != paNoError) {
        rexmpp_log(session->s, LOG_ERR,
                   "Failed to close a PortAudio stream: %s",
                   Pa_GetErrorText(err));
      }
      session->pa_stream = NULL;
    }
#ifdef HAVE_OPUS
    if (session->opus_enc != NULL) {
      opus_encoder_destroy(session->opus_enc);
      session->opus_enc = NULL;
    }
    if (session->opus_dec != NULL) {
      opus_decoder_destroy(session->opus_dec);
      session->opus_dec = NULL;
    }
#endif  /* HAVE_OPUS */
    for (i = 0; i < 2; i++) {
      rexmpp_jingle_component_t *comp = &session->component[i];
      if (comp->dtls_state == REXMPP_TLS_ACTIVE ||
          comp->dtls_state == REXMPP_TLS_CLOSING ||
          comp->dtls_state == REXMPP_TLS_CLOSED) {
        /* SRTP structures are allocated upon a TLS connection, so
           using the TLS state to find when they should be
           deallocated. */
        if (comp->srtp_in != NULL) {
          srtp_dealloc(comp->srtp_in);
        }
        if (comp->srtp_out != NULL) {
          srtp_dealloc(comp->srtp_out);
        }
      }
      if (comp->dtls_state == REXMPP_TLS_HANDSHAKE ||
          comp->dtls_state == REXMPP_TLS_ACTIVE ||
          comp->dtls_state == REXMPP_TLS_CLOSING ||
          comp->dtls_state == REXMPP_TLS_CLOSED) {
        rexmpp_tls_session_free(comp->dtls);
        rexmpp_tls_ctx_free(comp->dtls);
        comp->dtls = NULL;
        comp->dtls_state = REXMPP_TLS_INACTIVE;
      }
    }
    if (session->ice_agent != NULL) {
      nice_agent_close_async(session->ice_agent, NULL, NULL);
      g_object_unref(session->ice_agent);
      session->ice_agent = NULL;
    }
    if (session->stun_host != NULL) {
      free(session->stun_host);
      session->stun_host = NULL;
    }
    if (session->turn_host != NULL) {
      free(session->turn_host);
      session->turn_host = NULL;
    }
    if (session->turn_username != NULL) {
      free(session->turn_username);
      session->turn_username = NULL;
    }
    if (session->turn_password != NULL) {
      free(session->turn_password);
      session->turn_password = NULL;
    }
  }
#endif  /* ENABLE_CALLS */
  free(session);
}

void rexmpp_jingle_session_delete (rexmpp_t *s, rexmpp_jingle_session_t *sess) {
  if (sess == NULL) {
    return;
  }
  rexmpp_log(s, LOG_DEBUG, "Removing Jingle session %s", sess->sid);
  rexmpp_jingle_session_t *cur = s->jingle->sessions, *prev = NULL;
  while (cur != NULL) {
    if (sess == cur) {
      if (prev == NULL) {
        s->jingle->sessions = cur->next;
      } else {
        prev->next = cur->next;
      }
      rexmpp_jingle_session_destroy(sess);
      return;
    }
    prev = cur;
    cur = cur->next;
  }
}

void rexmpp_jingle_session_delete_by_id (rexmpp_t *s, const char *sid) {
  rexmpp_jingle_session_delete(s, rexmpp_jingle_session_by_id(s, sid));
}

int rexmpp_jingle_session_add (rexmpp_t *s, rexmpp_jingle_session_t *sess) {
  uint32_t sessions_num = 0;
  rexmpp_jingle_session_t *cur = s->jingle->sessions;
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
  sess->next = s->jingle->sessions;
  s->jingle->sessions = sess;
  return 1;
}

int rexmpp_jingle_ice_agent_init (rexmpp_jingle_session_t *sess);

rexmpp_jingle_session_t *
rexmpp_jingle_session_create (rexmpp_t *s,
                              char *jid,
                              char *sid,
                              enum rexmpp_jingle_session_type type,
                              int initiator)
{
  rexmpp_jingle_session_t *sess = malloc(sizeof(rexmpp_jingle_session_t));
  if (sess != NULL) {
    sess->s = s;
    sess->jid = jid;
    sess->sid = sid;
    sess->type = type;
    sess->initiator = initiator;
    sess->initiate = NULL;
    sess->accept = NULL;
    sess->ibb_fh = NULL;
    sess->ibb_sid = NULL;
    sess->ibb_seq = 0;
#ifdef ENABLE_CALLS
    int i;
    for (i = 0; i < 2; i++) {
      sess->component[i].component_id = i + 1;
      sess->component[i].session = sess;
      sess->component[i].s = s;
      sess->component[i].dtls_state = REXMPP_TLS_INACTIVE;
      sess->component[i].dtls = rexmpp_tls_ctx_new(s, 1);
      sess->component[i].srtp_out = NULL;
      sess->component[i].srtp_in = NULL;
    }
    sess->ice_agent = NULL;
    sess->rtcp_mux = s->jingle_prefer_rtcp_mux;

    sess->stun_host = NULL;
    sess->stun_port = 0;
    sess->turn_host = NULL;
    sess->turn_port = 0;
    sess->turn_username = NULL;
    sess->turn_password = NULL;

    sess->ring_buffers.capture.read_pos = 0;
    sess->ring_buffers.capture.write_pos = 0;
    sess->ring_buffers.playback.read_pos = 0;
    sess->ring_buffers.playback.write_pos = 0;
    sess->codec = REXMPP_CODEC_UNDEFINED;
    sess->payload_type = 0;
#ifdef HAVE_OPUS
    sess->opus_enc = NULL;
    sess->opus_dec = NULL;
#endif  /* HAVE_POUS */
#endif  /* ENABLE_CALLS */
    if (! rexmpp_jingle_session_add(s, sess)) {
      rexmpp_jingle_session_destroy(sess);
      sess = NULL;
    }
  } else {
    rexmpp_log(s, LOG_ERR, "Failed to allocate memory for a Jingle session");
  }
  return sess;
}

rexmpp_jingle_session_t *
rexmpp_jingle_session_by_ibb_sid (rexmpp_t *s, const char *ibb_sid) {
  if (ibb_sid == NULL) {
    return NULL;
  }
  rexmpp_jingle_session_t *cur = s->jingle->sessions;
  while (cur != NULL) {
    if (cur->type == REXMPP_JINGLE_SESSION_FILE &&
        strcmp(cur->ibb_sid, ibb_sid) == 0) {
      return cur;
    }
    cur = cur->next;
  }
  rexmpp_log(s, LOG_WARNING,
             "No Jingle session with ibb_sid %s found", ibb_sid);
  return NULL;
}

int rexmpp_jingle_init (rexmpp_t *s) {
  s->jingle = malloc(sizeof(struct rexmpp_jingle_ctx));
  s->jingle->sessions = NULL;
#ifdef ENABLE_CALLS
  g_networking_init();
  srtp_init();
  s->jingle->gloop = g_main_loop_new(NULL, FALSE);
  Pa_Initialize();
  nice_debug_enable(1);
#endif  /* ENABLE_CALLS */
  return 0;
}

void rexmpp_jingle_stop (rexmpp_t *s) {
  while (s->jingle->sessions != NULL) {
    rexmpp_jingle_session_delete(s, s->jingle->sessions);
  }
#ifdef ENABLE_CALLS
  g_main_loop_quit(s->jingle->gloop);
  s->jingle->gloop = NULL;
  srtp_shutdown();
  Pa_Terminate();
#endif  /* ENABLE_CALLS */
  free(s->jingle);
  s->jingle = NULL;
}


void rexmpp_jingle_accept_file_cb (rexmpp_t *s,
                                   void *ptr,
                                   rexmpp_xml_t *request,
                                   rexmpp_xml_t *response,
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
  session->ibb_fh = fopen(path, "wb");
  if (session->ibb_fh == NULL) {
    rexmpp_log(s, LOG_ERR, "Failed to open %s for writing: %s",
               path, strerror(errno));
    return REXMPP_E_OTHER;
  }
  rexmpp_xml_t *jingle = session->initiate;
  rexmpp_xml_t *content = rexmpp_xml_find_child(jingle, "urn:xmpp:jingle:1", "content");

  rexmpp_xml_t *new_jingle =
    rexmpp_xml_new_elem("jingle", "urn:xmpp:jingle:1");
  rexmpp_xml_add_attr(new_jingle, "action", "session-accept");
  rexmpp_xml_add_attr(new_jingle, "responder", s->assigned_jid.full);
  rexmpp_xml_add_attr(new_jingle, "sid", session->sid);
  rexmpp_xml_add_child(new_jingle, rexmpp_xml_clone(content));
  session->accept = rexmpp_xml_clone(new_jingle);
  return rexmpp_iq_new(s, "set", session->jid, new_jingle,
                       rexmpp_jingle_accept_file_cb, strdup(session->sid));
}

rexmpp_err_t
rexmpp_jingle_accept_file_by_id (rexmpp_t *s,
                                 const char *sid,
                                 const char *path)
{
  rexmpp_jingle_session_t *session = rexmpp_jingle_session_by_id(s, sid);
  if (session == NULL) {
    return REXMPP_E_OTHER;
  }
  return rexmpp_jingle_accept_file(s, session, path);
}

void rexmpp_jingle_session_terminate_cb (rexmpp_t *s,
                                         void *ptr,
                                         rexmpp_xml_t *request,
                                         rexmpp_xml_t *response,
                                         int success)
{
  (void)request;
  (void)response;
  char *sid = ptr;
  if (! success) {
    rexmpp_log(s, LOG_ERR, "Failed to terminate session %s, removing anyway",
               sid);
  }
  free(sid);
}

rexmpp_err_t
rexmpp_jingle_session_terminate (rexmpp_t *s,
                                 const char *sid,
                                 rexmpp_xml_t *reason_node,
                                 const char *reason_text)
{
  rexmpp_jingle_session_t *session = rexmpp_jingle_session_by_id(s, sid);
  if (session == NULL) {
    return REXMPP_E_OTHER;
  }
  rexmpp_xml_t *jingle =
    rexmpp_xml_new_elem("jingle", "urn:xmpp:jingle:1");
  rexmpp_xml_add_attr(jingle, "action", "session-terminate");
  rexmpp_xml_add_attr(jingle, "sid", sid);
  rexmpp_xml_t *reason =
    rexmpp_xml_new_elem("reason", "urn:xmpp:jingle:1");
  if (reason_text != NULL) {
    rexmpp_xml_t *text =
      rexmpp_xml_new_elem("text", "urn:xmpp:jingle:1");
    rexmpp_xml_add_text(text, reason_text);
    rexmpp_xml_add_child(reason, text);
  }
  rexmpp_xml_add_child(reason, reason_node);
  rexmpp_xml_add_child(jingle, reason);
  rexmpp_err_t ret = rexmpp_iq_new(s, "set", session->jid, jingle,
                                   rexmpp_jingle_session_terminate_cb,
                                   strdup(sid));
  rexmpp_jingle_session_delete_by_id(s, sid);
  return ret;
}

void rexmpp_jingle_send_file_cb (rexmpp_t *s,
                                 void *ptr,
                                 rexmpp_xml_t *request,
                                 rexmpp_xml_t *response,
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
  /* Open the file and calculate its hash before allocating the other
     things, so we can easily return on failure. */
  FILE *fh = fopen(path, "rb");
  if (fh == NULL) {
    rexmpp_log(s, LOG_ERR, "Failed to open %s for reading", path);
    return REXMPP_E_OTHER;
  }

  char buf[4096];
  gcry_md_hd_t hd;
  gcry_error_t err = gcry_md_open(&hd, GCRY_MD_SHA256, 0);
  if (err != GPG_ERR_NO_ERROR) {
    rexmpp_log(s, LOG_ERR, "Failed to create a MD object: %s",
               gcry_strerror(err));
    fclose(fh);
    return REXMPP_E_OTHER;
  }
  err = gcry_md_enable(hd, GCRY_MD_SHA3_256);
  if (err != GPG_ERR_NO_ERROR) {
    rexmpp_log(s, LOG_ERR, "Failed to add sha3-256 to the MD object: %s",
               gcry_strerror(err));
    fclose(fh);
    return REXMPP_E_OTHER;
  }
  size_t len = fread(buf, 1, 4096, fh);
  while (len > 0) {
    gcry_md_write(hd, buf, len);
    len = fread(buf, 1, 4096, fh);
  }
  gcry_md_final(hd);

  char *sid = rexmpp_gen_id(s);
  char *ibb_sid = rexmpp_gen_id(s);

  rexmpp_xml_t *jingle =
    rexmpp_xml_new_elem("jingle", "urn:xmpp:jingle:1");
  rexmpp_xml_add_attr(jingle, "action", "session-initiate");
  rexmpp_xml_add_attr(jingle, "sid", sid);
  rexmpp_xml_add_attr(jingle, "initiator", s->assigned_jid.full);

  rexmpp_xml_t *content =
    rexmpp_xml_new_elem("content", "urn:xmpp:jingle:1");
  rexmpp_xml_add_attr(content, "creator", "initiator");
  rexmpp_xml_add_attr(content, "name", "IBB file");
  rexmpp_xml_add_child(jingle, content);

  rexmpp_xml_t *transport =
    rexmpp_xml_new_elem("transport", "urn:xmpp:jingle:transports:ibb:1");
  rexmpp_xml_add_attr(transport, "block-size", "4096");
  rexmpp_xml_add_attr(transport, "sid", ibb_sid);
  rexmpp_xml_add_child(content, transport);
  rexmpp_xml_t *description =
    rexmpp_xml_new_elem("description", "urn:xmpp:jingle:apps:file-transfer:5");
  rexmpp_xml_add_child(content, description);
  rexmpp_xml_t *file =
    rexmpp_xml_new_elem("file", "urn:xmpp:jingle:apps:file-transfer:5");
  rexmpp_xml_add_child(description, file);
  rexmpp_xml_t *file_name =
    rexmpp_xml_new_elem("name", "urn:xmpp:jingle:apps:file-transfer:5");
  rexmpp_xml_add_text(file_name, basename(path));
  rexmpp_xml_add_child(file, file_name);

  char *hash_base64 = NULL;
  size_t hash_base64_len = 0;
  rexmpp_base64_to((char*)gcry_md_read(hd, GCRY_MD_SHA256),
                   gcry_md_get_algo_dlen(GCRY_MD_SHA256),
                   &hash_base64,
                   &hash_base64_len);
  rexmpp_xml_t *file_hash =
    rexmpp_xml_new_elem("hash", "urn:xmpp:hashes:2");
  rexmpp_xml_add_attr(file_hash, "algo", "sha-256");
  rexmpp_xml_add_text(file_hash, hash_base64);
  free(hash_base64);
  rexmpp_xml_add_child(file, file_hash);

  hash_base64 = NULL;
  hash_base64_len = 0;
  rexmpp_base64_to((char*)gcry_md_read(hd, GCRY_MD_SHA3_256),
                   gcry_md_get_algo_dlen(GCRY_MD_SHA3_256),
                   &hash_base64,
                   &hash_base64_len);
  file_hash = rexmpp_xml_new_elem("hash", "urn:xmpp:hashes:2");
  rexmpp_xml_add_attr(file_hash, "algo", "sha3-256");
  rexmpp_xml_add_text(file_hash, hash_base64);
  free(hash_base64);
  rexmpp_xml_add_child(file, file_hash);

  gcry_md_close(hd);

  long fsize = ftell(fh);
  fseek(fh, 0, SEEK_SET);
  snprintf(buf, 11, "%ld", fsize);
  rexmpp_xml_t *file_size =
    rexmpp_xml_new_elem("size", "urn:xmpp:jingle:apps:file-transfer:5");
  rexmpp_xml_add_text(file_size, buf);
  rexmpp_xml_add_child(file, file_size);

  rexmpp_jingle_session_t *sess =
    rexmpp_jingle_session_create(s, strdup(jid), sid, REXMPP_JINGLE_SESSION_FILE, 1);
  if (sess != NULL) {
    sess->initiate = rexmpp_xml_clone(jingle);
    sess->ibb_sid = ibb_sid;
    sess->ibb_fh = fh;
    return rexmpp_iq_new(s, "set", sess->jid, jingle,
                         rexmpp_jingle_send_file_cb, strdup(sess->sid));
  } else {
    return REXMPP_E_OTHER;
  }
}


void rexmpp_jingle_ibb_close_cb (rexmpp_t *s,
                                 void *ptr,
                                 rexmpp_xml_t *request,
                                 rexmpp_xml_t *response,
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

void rexmpp_jingle_ibb_send_cb (rexmpp_t *s,
                                void *ptr,
                                rexmpp_xml_t *request,
                                rexmpp_xml_t *response,
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
  if (feof(session->ibb_fh)) {
    rexmpp_xml_t *close =
      rexmpp_xml_new_elem("close", "http://jabber.org/protocol/ibb");
    rexmpp_xml_add_attr(close, "sid", session->ibb_sid);
    rexmpp_iq_new(s, "set", session->jid, close,
                  rexmpp_jingle_ibb_close_cb, sid);
    return;
  } else {
    char buf[4096];
    size_t len = fread(buf, 1, 4096, session->ibb_fh);
    if (len > 0) {
      rexmpp_xml_t *data =
        rexmpp_xml_new_elem("data", "http://jabber.org/protocol/ibb");
      rexmpp_xml_add_attr(data, "sid", session->ibb_sid);
      char *out = NULL;
      size_t out_len = 0;
      rexmpp_base64_to(buf, len, &out, &out_len);
      rexmpp_xml_add_text(data, out);
      free(out);
      snprintf(buf, 11, "%u", session->ibb_seq);
      rexmpp_xml_add_attr(data, "seq", buf);
      session->ibb_seq++;
      rexmpp_iq_new(s, "set", session->jid, data,
                    rexmpp_jingle_ibb_send_cb, sid);
      return;
    } else {
      rexmpp_log(s, LOG_ERR, "Failed to read from a file: %s ", strerror(errno));
      rexmpp_jingle_session_terminate(s, sid,
                                      rexmpp_xml_new_elem("media-error",
                                                          "urn:xmpp:jingle:1"),
                                      "File reading error");
    }
  }
  free(sid);
}

#ifdef ENABLE_CALLS
void rexmpp_jingle_call_cb (rexmpp_t *s,
                            void *ptr,
                            rexmpp_xml_t *request,
                            rexmpp_xml_t *response,
                            int success)
{
  (void)request;
  (void)response;
  char *sid = ptr;
  if (! success) {
    rexmpp_log(s, LOG_ERR, "Failed to initiate a call for sid %s", sid);
    rexmpp_jingle_session_delete_by_id(s, sid);
  }
  free(sid);
}

void
rexmpp_jingle_ice_udp_add_remote (rexmpp_jingle_session_t *sess,
                                  rexmpp_xml_t *transport)
{
  if (sess->ice_agent == NULL) {
    /* Must be an incoming call; just add candidates to
       session-initiate's transport. */
    rexmpp_xml_t *old_transport =
      rexmpp_xml_find_child(rexmpp_xml_find_child(sess->initiate,
                                                  "urn:xmpp:jingle:1",
                                                  "content"),
                            "urn:xmpp:jingle:transports:ice-udp:1",
                            "transport");
    rexmpp_xml_t *candidate = rexmpp_xml_first_elem_child(transport);
    while (rexmpp_xml_match(candidate, "urn:xmpp:jingle:transports:ice-udp:1",
                            "candidate")) {
      rexmpp_xml_add_child(old_transport, rexmpp_xml_clone(candidate));
      candidate = rexmpp_xml_next_elem_sibling(candidate);
    }
    return;
  }
  const char *ufrag = rexmpp_xml_find_attr_val(transport, "ufrag");
  const char *password = rexmpp_xml_find_attr_val(transport, "pwd");
  nice_agent_set_remote_credentials(sess->ice_agent, sess->ice_stream_id,
                                    ufrag, password);

  int component_id;

  for (component_id = 1; component_id <= (sess->rtcp_mux ? 1 : 2); component_id++) {
    GSList *remote_candidates =
      nice_agent_get_remote_candidates(sess->ice_agent,
                                       sess->ice_stream_id,
                                       component_id);
    rexmpp_xml_t *candidate = rexmpp_xml_first_elem_child(transport);
    while (candidate != NULL) {
      if (rexmpp_xml_match(candidate, "urn:xmpp:jingle:transports:ice-udp:1",
                              "candidate")) {
        const char *component = rexmpp_xml_find_attr_val(candidate, "component");
        if (component[0] == component_id + '0') {
          const char *type_str = rexmpp_xml_find_attr_val(candidate, "type");
          int type_n = NICE_CANDIDATE_TYPE_HOST;
          if (strcmp(type_str, "host") == 0) {
            type_n = NICE_CANDIDATE_TYPE_HOST;
          } else if (strcmp(type_str, "srflx") == 0) {
            type_n = NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
          } else if (strcmp(type_str, "prflx") == 0) {
            type_n = NICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
          } else if (strcmp(type_str, "relay") == 0) {
            type_n = NICE_CANDIDATE_TYPE_RELAYED;
          }
          NiceCandidate *c = nice_candidate_new(type_n);
          c->component_id = component_id;
          c->stream_id = sess->ice_stream_id;

          const char *foundation = rexmpp_xml_find_attr_val(candidate, "foundation");
          strncpy(c->foundation, foundation, NICE_CANDIDATE_MAX_FOUNDATION - 1);
          c->foundation[NICE_CANDIDATE_MAX_FOUNDATION - 1] = 0;

          c->transport = NICE_CANDIDATE_TRANSPORT_UDP;

          const char *priority = rexmpp_xml_find_attr_val(candidate, "priority");
          c->priority = atoi(priority);

          const char *ip = rexmpp_xml_find_attr_val(candidate, "ip");
          if (! nice_address_set_from_string(&c->addr, ip)) {
            rexmpp_log(sess->s, LOG_ERR,
                       "Failed to parse an ICE-UDP candidate's address: %s",
                       ip);
          }

          const char *port = rexmpp_xml_find_attr_val(candidate, "port");
          nice_address_set_port(&c->addr, atoi(port));

          remote_candidates = g_slist_prepend(remote_candidates, c);
        }
      }
      candidate = rexmpp_xml_next_elem_sibling(candidate);
    }
    if (remote_candidates != NULL) {
      rexmpp_log(sess->s, LOG_DEBUG,
                 "Setting %d remote candidates for component %d",
                 g_slist_length(remote_candidates),
                 component_id);
      nice_agent_set_remote_candidates(sess->ice_agent, sess->ice_stream_id,
                                       component_id, remote_candidates);
      g_slist_free_full(remote_candidates, (GDestroyNotify)&nice_candidate_free);
    } else {
      rexmpp_log(sess->s, LOG_WARNING,
                 "No remote candidates for component %d",
                 component_id);
    }
  }
}

/* Checks whether we are in the active (client) role for DTLS, based
   on either "session-initiate" or "session-accept" message. */
int rexmpp_jingle_dtls_is_active (rexmpp_jingle_session_t *sess, int in_initiate) {
  rexmpp_xml_t *fingerprint =
    rexmpp_xml_find_child
    (rexmpp_xml_find_child
     (rexmpp_xml_find_child
      (in_initiate ? sess->initiate : sess->accept,
       "urn:xmpp:jingle:1", "content"),
      "urn:xmpp:jingle:transports:ice-udp:1", "transport"),
     "urn:xmpp:jingle:apps:dtls:0", "fingerprint");
  if (fingerprint == NULL) {
    rexmpp_log(sess->s, LOG_ERR, "No fingerprint in the 'session-%s' Jingle element",
               in_initiate ? "initiate" : "accept");
    return 0;
  }
  const char *fingerprint_setup = rexmpp_xml_find_attr_val(fingerprint, "setup");
  if (fingerprint_setup == NULL) {
    rexmpp_log(sess->s, LOG_ERR, "No 'setup' attribute for a fingerprint element");
    return 0;
  }
  int active = 0;
  if (sess->initiator) {
    if (in_initiate) {
      active = (strcmp(fingerprint_setup, "active") == 0);
    } else {
      active = (strcmp(fingerprint_setup, "active") != 0);
    }
  } else {
    if (in_initiate) {
      active = (strcmp(fingerprint_setup, "active") != 0);
    } else {
      active = (strcmp(fingerprint_setup, "active") == 0);
    }
  }
  return active;
}


void rexmpp_transport_info_call_cb (rexmpp_t *s,
                                    void *ptr,
                                    rexmpp_xml_t *request,
                                    rexmpp_xml_t *response,
                                    int success)
{
  (void)request;
  (void)response;
  char *sid = ptr;
  if (! success) {
    rexmpp_log(s, LOG_ERR,
               "Failed to send additional candidate for Jingle session %s",
               sid);
  }
  free(ptr);
}

void
rexmpp_jingle_candidate_gathering_done_cb (NiceAgent *agent,
                                           guint stream_id,
                                           gpointer data)
{
  rexmpp_jingle_session_t *sess = data;

  rexmpp_log(sess->s, LOG_DEBUG, "ICE agent candidate gathering is done");

  /* We'll need a fingerprint a bit later, but checking it before
     allocating other things. */

  /* TODO: should use DTLS credentials, not regular TLS ones. Using
     these for now because DTLS ones are not allocated yet, and they
     are the same anyway. */
  char fp[32], fp_str[32 * 3 + 1];
  size_t fp_size = 32;

  if (rexmpp_tls_session_fp(sess->s, sess->s->tls, "sha-256", fp, fp_str, &fp_size)) {
    return;
  }

  rexmpp_xml_t *jingle = rexmpp_xml_new_elem("jingle", "urn:xmpp:jingle:1");
  rexmpp_xml_add_attr(jingle, "sid", sess->sid);

  rexmpp_xml_t *content = rexmpp_xml_new_elem("content", "urn:xmpp:jingle:1");
  rexmpp_xml_add_attr(content, "creator", "initiator");
  rexmpp_xml_add_attr(content, "senders", "both");
  rexmpp_xml_t *description;
  if (sess->initiator) {
    /* We are the intiator: send the predefined options. */
    rexmpp_xml_add_attr(jingle, "action", "session-initiate");
    rexmpp_xml_add_attr(jingle, "initiator", sess->s->assigned_jid.full);
    rexmpp_xml_add_attr(content, "name", "call");

    /* https://datatracker.ietf.org/doc/html/rfc4568 */
    rexmpp_xml_t *encryption =
      rexmpp_xml_new_elem("encryption", "urn:xmpp:jingle:apps:rtp:1");
    rexmpp_xml_add_attr(encryption, "required", "true");
    rexmpp_xml_add_child(content, encryption);
    rexmpp_xml_t *crypto =
      rexmpp_xml_new_elem("crypto", "urn:xmpp:jingle:apps:rtp:1");
    rexmpp_xml_add_attr(crypto, "crypto-suite", "AES_CM_128_HMAC_SHA1_80");
    rexmpp_xml_add_attr(crypto, "tag", "1");
    rexmpp_xml_add_child(encryption, crypto);

    description = rexmpp_xml_clone(sess->s->jingle_rtp_description);
  } else {
    /* Accepting the call, will have to compare payload type options
       to supported and preferred ones, and pick some from those. */
    rexmpp_xml_t *init_jingle = sess->initiate;
    rexmpp_xml_t *init_content =
      rexmpp_xml_find_child(init_jingle, "urn:xmpp:jingle:1", "content");
    const char *init_content_name = rexmpp_xml_find_attr_val(init_content, "name");
    if (init_content_name != NULL) {
      rexmpp_xml_add_attr(content, "name", init_content_name);
    } else {
      rexmpp_log(sess->s, LOG_ERR,
                 "Empty content name for Jingle session %s with %s",
                 sess->sid, sess->jid);
    }
    rexmpp_xml_add_attr(jingle, "action", "session-accept");
    rexmpp_xml_add_attr(jingle, "initiator", sess->jid);
    rexmpp_xml_add_attr(jingle, "responder", sess->s->assigned_jid.full);

    description = rexmpp_xml_clone(sess->s->jingle_rtp_description);
    /* Find the first matching payload-type and add that */
    rexmpp_xml_t *pl_type =
      rexmpp_xml_first_elem_child(sess->s->jingle_rtp_description);
    rexmpp_xml_t *selected_pl = NULL;
    while (pl_type != NULL) {
      if (rexmpp_xml_match(pl_type, "urn:xmpp:jingle:apps:rtp:1", "payload-type")) {
        const char *pl_id = rexmpp_xml_find_attr_val(pl_type, "id");
        if (pl_id != NULL) {
          int pl_id_num = atoi(pl_id);
          rexmpp_xml_t *proposed_pl_type =
            rexmpp_xml_first_elem_child
            (rexmpp_xml_find_child
             (rexmpp_xml_find_child(sess->initiate,
                                    "urn:xmpp:jingle:1", "content"),
              "urn:xmpp:jingle:apps:rtp:1", "description"));
          while (proposed_pl_type != NULL && selected_pl == NULL) {
            if (rexmpp_xml_match(proposed_pl_type, "urn:xmpp:jingle:apps:rtp:1", "payload-type")) {
              const char *proposed_pl_id = rexmpp_xml_find_attr_val(proposed_pl_type, "id");
              if (proposed_pl_id != NULL) {
                int proposed_pl_id_num = atoi(proposed_pl_id);
                if (pl_id_num < 96 && pl_id_num == proposed_pl_id_num) {
                  selected_pl = pl_type;
                } else {
                  const char *pl_name =
                    rexmpp_xml_find_attr_val(pl_type, "name");
                  if (pl_name != NULL) {
                    const char *proposed_pl_name =
                      rexmpp_xml_find_attr_val(proposed_pl_type, "name");
                    if (proposed_pl_name != NULL) {
                      if (strcmp(pl_name, proposed_pl_name) == 0) {
                        /* todo: compare clock rates, numbers of
                           channels, parameters */
                        selected_pl = pl_type;
                      }
                    }
                  }
                }
              }
            }
            proposed_pl_type = rexmpp_xml_next_elem_sibling(proposed_pl_type);
          }
        } else {
          rexmpp_log(sess->s, LOG_ERR,
                     "No 'id' specified for a payload-type element.");
        }
      }
      pl_type = pl_type->next;
    }
    if (selected_pl != NULL) {
      rexmpp_xml_add_child(description, rexmpp_xml_clone(selected_pl));
    } else {
      rexmpp_log(sess->s, LOG_ERR, "No suitable payload type found");
      /* todo: fail if it's NULL, though it shouldn't happen, since
         PCMU and PCMA are mandatory */
    }
  }

  rexmpp_xml_add_child(jingle, content);
  rexmpp_xml_add_child(content, description);

  if (sess->rtcp_mux) {
    rexmpp_xml_t *rtcp_mux =
      rexmpp_xml_new_elem("rtcp-mux", "urn:xmpp:jingle:apps:rtp:1");
    rexmpp_xml_add_child(description, rtcp_mux);
  }

  rexmpp_xml_t *transport =
    rexmpp_xml_new_elem("transport", "urn:xmpp:jingle:transports:ice-udp:1");
  gchar *ufrag = NULL;
  gchar *password = NULL;
  nice_agent_get_local_credentials(agent, stream_id, &ufrag, &password);
  rexmpp_xml_add_attr(transport, "ufrag", ufrag);
  rexmpp_xml_add_attr(transport, "pwd", password);
  g_free(ufrag);
  g_free(password);
  rexmpp_xml_add_child(content, transport);
  int component_id;
  rexmpp_xml_t *postponed_candidates = NULL;
  for (component_id = 1; component_id <= (sess->rtcp_mux ? 1 : 2); component_id++) {
    GSList *candidates = nice_agent_get_local_candidates(agent, stream_id, component_id);
    GSList *cand_cur = candidates;
    int cand_num = 0;
    while (cand_cur != NULL) {
      rexmpp_xml_t *candidate =
        rexmpp_xml_new_elem("candidate", "urn:xmpp:jingle:transports:ice-udp:1");
      char buf[INET6_ADDRSTRLEN];
      NiceCandidate *c = (NiceCandidate *)cand_cur->data;
      snprintf(buf, 11, "%u", component_id);
      rexmpp_xml_add_attr(candidate, "component", buf);
      rexmpp_xml_add_attr(candidate, "foundation", c->foundation);
      rexmpp_xml_add_attr(candidate, "generation", "0");
      char *cid = rexmpp_gen_id(sess->s);
      rexmpp_xml_add_attr(candidate, "id", cid);
      free(cid);
      nice_address_to_string(&c->addr, buf);
      rexmpp_xml_add_attr(candidate, "ip", buf);
      snprintf(buf, 11, "%u", nice_address_get_port(&c->addr));
      rexmpp_xml_add_attr(candidate, "port", buf);
      rexmpp_xml_add_attr(candidate, "network", "0");
      rexmpp_xml_add_attr(candidate, "protocol", "udp");
      snprintf(buf, 11, "%u", c->priority);
      rexmpp_xml_add_attr(candidate, "priority", buf);
      char *nice_type[] = {"host", "srflx", "prflx", "relay"};
      if (c->type < 4) {
        rexmpp_xml_add_attr(candidate, "type", nice_type[c->type]);
      }
      /* Can't send too many candidates, since stanza sizes are usually
         limited, and then it breaks the stream. Limiting to 10 per
         component, sending the rest later, via transport-info. */
      if (cand_num < 10) {
        rexmpp_xml_add_child(transport, candidate);
      } else {
        rexmpp_xml_t *jingle_ti =
          rexmpp_xml_new_elem("jingle", "urn:xmpp:jingle:1");
        rexmpp_xml_add_attr(jingle_ti, "sid", sess->sid);
        rexmpp_xml_add_attr(jingle_ti, "action", "transport-info");
        rexmpp_xml_t *content_copy = rexmpp_xml_clone(content);
        rexmpp_xml_t *transport_copy = rexmpp_xml_clone(transport);
        rexmpp_xml_add_child(jingle_ti, content_copy);
        rexmpp_xml_add_child(content_copy, transport_copy);
        rexmpp_xml_add_child(transport_copy, candidate);
        jingle_ti->next = postponed_candidates;
        postponed_candidates = jingle_ti;
      }
      cand_cur = cand_cur->next;
      cand_num++;
    }
    if (candidates != NULL) {
      g_slist_free_full(candidates, (GDestroyNotify)&nice_candidate_free);
    }
  }

  rexmpp_xml_t *fingerprint =
    rexmpp_xml_new_elem("fingerprint", "urn:xmpp:jingle:apps:dtls:0");
  rexmpp_xml_add_attr(fingerprint, "hash", "sha-256");
  if (sess->initiator) {
    rexmpp_xml_add_attr(fingerprint, "setup", "actpass");
  } else if (rexmpp_jingle_dtls_is_active(sess, 1)) {
    rexmpp_xml_add_attr(fingerprint, "setup", "active");
  } else {
    rexmpp_xml_add_attr(fingerprint, "setup", "passive");
  }

  rexmpp_xml_add_text(fingerprint, fp_str);
  rexmpp_xml_add_child(transport, fingerprint);

  if (sess->initiator) {
    sess->initiate = rexmpp_xml_clone(jingle);
  } else {
    sess->accept = rexmpp_xml_clone(jingle);
    rexmpp_jingle_session_configure_audio(sess);
    rexmpp_jingle_run_audio(sess);
  }

  rexmpp_iq_new(sess->s, "set", sess->jid, jingle,
                rexmpp_jingle_call_cb, strdup(sess->sid));

  /* Now send transport-info messages with candidates that didn't fit
     initially. */
  while (postponed_candidates != NULL) {
    rexmpp_xml_t *pc_next = postponed_candidates->next;
    postponed_candidates->next = NULL;
    rexmpp_iq_new(sess->s, "set", sess->jid, postponed_candidates,
                  rexmpp_transport_info_call_cb, strdup(sess->sid));
    postponed_candidates = pc_next;
  }
}

ssize_t
rexmpp_jingle_dtls_push_func (void *p, const void *data, size_t size)
{
  rexmpp_jingle_component_t *comp = p;
  rexmpp_jingle_session_t *sess = comp->session;
  return nice_agent_send(sess->ice_agent, sess->ice_stream_id,
                         comp->component_id, size, data);
}

rexmpp_tls_err_t
rexmpp_jingle_dtls_pull_func (void *p,
                              void *data,
                              size_t size,
                              ssize_t *received)
{
  rexmpp_jingle_component_t *comp = p;
  char *tls_buf = comp->dtls->dtls_buf;
  size_t *tls_buf_len = &(comp->dtls->dtls_buf_len);

  rexmpp_tls_err_t ret = REXMPP_TLS_SUCCESS;
  if (*tls_buf_len > 0) {
    if (size >= *tls_buf_len) {
      memcpy(data, tls_buf, *tls_buf_len);
      *received = *tls_buf_len;
      *tls_buf_len = 0;
    } else {
      if (size > DTLS_SRTP_BUF_SIZE) {
        size = DTLS_SRTP_BUF_SIZE;
      }
      memcpy(data, tls_buf, size);
      memmove(tls_buf, tls_buf + size, DTLS_SRTP_BUF_SIZE - size);
      *received = size;
      *tls_buf_len = *tls_buf_len - size;
    }
  } else {
    ret = REXMPP_TLS_E_AGAIN;
  }
  return ret;
}

/* The timeout is always zero for DTLS. */
int rexmpp_jingle_dtls_pull_timeout_func (void *p,
                                          unsigned int ms)
{
  rexmpp_jingle_component_t *comp = p;
  rexmpp_jingle_session_t *sess = comp->session;
  if (comp->dtls->dtls_buf_len > 0) {
    return comp->dtls->dtls_buf_len;
  }

  fd_set rfds;
  struct timeval tv;

  struct sockaddr_in cli_addr;
  socklen_t cli_addr_size;
  int ret;
  char c;

  FD_ZERO(&rfds);
  int fd, nfds = -1;

  GPtrArray *sockets =
    nice_agent_get_sockets(sess->ice_agent,
                           sess->ice_stream_id, comp->component_id);
  guint i;
  for (i = 0; i < sockets->len; i++) {
    fd = g_socket_get_fd(sockets->pdata[i]);
    FD_SET(fd, &rfds);
    if (fd > nfds) {
      nfds = fd;
    }
  }
  g_ptr_array_unref(sockets);


  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;

  ret = select(nfds + 1, &rfds, NULL, NULL, &tv);
  if (ret < 0) {
    rexmpp_log(sess->s, LOG_WARNING,
               "DTLS pull function: select failed: %s",
               strerror(errno));
    return ret;
  }

  cli_addr_size = sizeof(cli_addr);
  ret = 0;
  sockets =
    nice_agent_get_sockets(sess->ice_agent,
                           sess->ice_stream_id, comp->component_id);
  for (i = 0; i < sockets->len; i++) {
    int err =
      recvfrom(g_socket_get_fd(sockets->pdata[i]), &c, 1, MSG_PEEK,
               (struct sockaddr *) &cli_addr, &cli_addr_size);
    if (err == -1) {
      /* ENOTCONN and EAGAIN are common here, but report other
         errors. */
      if (errno != ENOTCONN && errno != EAGAIN) {
        rexmpp_log(sess->s, LOG_WARNING,
                   "DTLS pull function: failed to peek a socket: %s",
                   strerror(errno));
      }
    } else {
      ret += err;
    }
  }
  g_ptr_array_unref(sockets);

  if (ret > 0) {
    return ret;
  }
  return 0;
}

const char *rexmpp_ice_component_state_text(int state) {
  switch (state) {
  case NICE_COMPONENT_STATE_DISCONNECTED: return "disconnected";
  case NICE_COMPONENT_STATE_GATHERING: return "gathering";
  case NICE_COMPONENT_STATE_CONNECTING: return "connecting";
  case NICE_COMPONENT_STATE_CONNECTED: return "connected";
  case NICE_COMPONENT_STATE_READY: return "ready";
  case NICE_COMPONENT_STATE_FAILED: return "failed";
  case NICE_COMPONENT_STATE_LAST: return "last";
  default: return "unknown";
  }
}

void
rexmpp_jingle_component_state_changed_cb (NiceAgent *agent,
                                          guint stream_id,
                                          guint component_id,
                                          guint state,
                                          gpointer data)
{
  rexmpp_jingle_session_t *sess = data;
  (void)agent;
  rexmpp_log(sess->s, LOG_DEBUG,
             "ICE agent component %d state for stream %d changed to %s",
             component_id, stream_id, rexmpp_ice_component_state_text(state));
  if (component_id < 1 || component_id > 2) {
    rexmpp_log(sess->s, LOG_CRIT, "Unexpected ICE component_id: %d",
               component_id);
    return;
  }
  if (state == NICE_COMPONENT_STATE_READY) {
    rexmpp_log(sess->s, LOG_INFO,
               "ICE connection established for Jingle session %s, "
               "ICE stream %d, component %d",
               sess->sid, stream_id, component_id);
    if (sess->component[component_id - 1].dtls_state != REXMPP_TLS_INACTIVE) {
      rexmpp_log(sess->s, LOG_WARNING,
                 "The connection for Jingle session %s and component %d"
                 " was established previously",
                 sess->sid, component_id);
      return;
    }

    rexmpp_jingle_component_t *comp = &(sess->component[component_id - 1]);
    rexmpp_dtls_connect(sess->s,
                        comp->dtls,
                        comp,
                        rexmpp_jingle_dtls_is_active(sess, 0));
    sess->component[component_id - 1].dtls_state = REXMPP_TLS_HANDSHAKE;
    rexmpp_tls_handshake(sess->s, comp->dtls);
  } else if (state == NICE_COMPONENT_STATE_FAILED) {
    rexmpp_log(sess->s, LOG_ERR,
               "ICE connection failed for Jingle session %s, ICE stream %d, component %d",
               sess->sid, stream_id, component_id);
    /* todo: maybe destroy the session if it failed for all the
       components */
  }
}

void
rexmpp_jingle_ice_recv_cb (NiceAgent *agent, guint stream_id, guint component_id,
                           guint len, gchar *gbuf, gpointer data)
{
  /* Demultiplexing here for DTLS and SRTP:
     https://datatracker.ietf.org/doc/html/rfc5764#section-5.1.2 */
  (void)agent;
  (void)stream_id;
  (void)component_id;
  uint8_t *buf = (uint8_t *)gbuf;
  rexmpp_jingle_component_t *comp = data;
  if (len == 0) {
    rexmpp_log(comp->s, LOG_WARNING, "Received an empty ICE message");
    return;
  }
  if (127 < buf[0] && buf[0] < 192) {
    int err;
    srtp_ctx_t *srtp_in;
    if (comp->dtls_state == REXMPP_TLS_ACTIVE) {
      srtp_in = comp->srtp_in;
    } else if (comp->session->component[0].dtls_state == REXMPP_TLS_ACTIVE) {
      /* Allow to reuse the first component's DTLS handshake/SRTP
         session. */
      srtp_in = comp->session->component[0].srtp_in;
    } else {
      rexmpp_log(comp->s, LOG_WARNING,
                 "Received an SRTP packet while DTLS is inactive");
      return;
    }
    if (srtp_in == NULL) {
      rexmpp_log(comp->s, LOG_WARNING,
                 "Received an SRTP packet while SRTP is not set up");
      return;
    }
    if (component_id == 1) {
      err = srtp_unprotect(srtp_in, buf, (int*)&len);
      if (err == srtp_err_status_auth_fail && comp->session->rtcp_mux) {
        /* Try to demultiplex. Maybe there's a better way to do it,
           but this will do for now. */
        err = srtp_unprotect_rtcp(srtp_in, buf, (int*)&len);
      }
    } else {
      err = srtp_unprotect_rtcp(srtp_in, buf, (int*)&len);
    }
    if (err) {
      rexmpp_log(comp->s, LOG_ERR, "SRT(C)P unprotect error %d on component %d",
                 err, component_id);
    } else {
      /* TODO: apparently sometimes there is more than one RTCP packet
         in the decrypted data; parse them all. */
      uint8_t version = (buf[0] & 0xc0) >> 6;
      if (version == 2 && len >= 12) {
        size_t i;
        uint8_t payload_type = buf[1] & 0x7f;
        uint8_t csrc_count = buf[0] & 0xF;
        uint16_t seq_num = ((uint16_t)buf[2] << 8) | buf[3];
        int data_start_pos = 12 + csrc_count * 4;

        /* Exclude possible RTCP packets here, RFC 5761 */
        if (component_id == 1
            && (payload_type < 64 || payload_type > 80)) {
          if ((seq_num > comp->session->rtp_last_seq_num)
              || (comp->session->rtp_last_seq_num > 65500)) {
            if ((comp->session->rtp_last_seq_num <= 65500)
                && (seq_num - comp->session->rtp_last_seq_num > 1)) {
              rexmpp_log(comp->s, LOG_NOTICE,
                         "%d RTP packets lost",
                         seq_num - comp->session->rtp_last_seq_num - 1);
            }
            struct ring_buf *playback = &(comp->session->ring_buffers.playback);

            /* Skip the RTP header. */
            if (payload_type == 0) {
              /* PCMU */
              for (i = data_start_pos; i < len; i++) {
                playback->buf[playback->write_pos] = rexmpp_pcmu_decode(buf[i]);
                playback->write_pos++;
                playback->write_pos %= PA_BUF_SIZE;
              }
            } else if (payload_type == 8) {
              /* PCMA */
              for (i = data_start_pos; i < len; i++) {
                playback->buf[playback->write_pos] = rexmpp_pcma_decode(buf[i]);
                playback->write_pos++;
                playback->write_pos %= PA_BUF_SIZE;
              }
            }
#ifdef HAVE_OPUS
            else if (payload_type == comp->session->payload_type
                     && comp->session->codec == REXMPP_CODEC_OPUS) {
              /* The same payload type as for output, which is Opus */
              opus_int16 decoded[5760 * 2];
              int decoded_len;
              decoded_len =
                opus_decode(comp->session->opus_dec,
                            (const unsigned char *)buf + data_start_pos,
                            len - data_start_pos,
                            decoded,
                            5760,
                            0);
              int j;
              for (j = 0; j < decoded_len; j++) {
                playback->buf[playback->write_pos] = decoded[j];
                playback->write_pos++;
                playback->write_pos %= PA_BUF_SIZE;
              }
            }
#endif  /* HAVE_OPUS */
            else {
              /* Some other payload type, possibly with a dynamic ID */
              rexmpp_xml_t *payload =
                rexmpp_jingle_session_payload_by_id(comp->session,
                                                    payload_type);
              const char *pl_name = rexmpp_xml_find_attr_val(payload, "name");
              rexmpp_log(comp->s, LOG_WARNING,
                         "Unhandled payload type %d, '%s'",
                         payload_type, pl_name);
            }
            comp->session->rtp_last_seq_num = seq_num;
          } else {
            rexmpp_log(comp->s, LOG_NOTICE,
                       "Out of order RTP packets received: %d after %d",
                       seq_num, comp->session->rtp_last_seq_num);
          }
        } else {
          uint8_t packet_type = buf[1];
          unsigned int pos = 0;
          unsigned int rtcp_len = (buf[2] << 8) | buf[3];
          if (packet_type == 200 && len >= 28) {
            uint32_t rtcp_ssrc =
              (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
            uint64_t rtcp_ntp_timestamp = 0;
            for (i = 8; i < 16; i++) {
              rtcp_ntp_timestamp <<= 8;
              rtcp_ntp_timestamp |= buf[i];
            }
            uint32_t rtcp_rtp_timestamp =
              (buf[16] << 24) | (buf[17] << 16) | (buf[18] << 8) | buf[19];
            uint32_t rtcp_packet_count =
              (buf[20] << 24) | (buf[21] << 16) | (buf[22] << 8) | buf[23];
            uint32_t rtcp_octet_count =
              (buf[24] << 24) | (buf[25] << 16) | (buf[26] << 8) | buf[27];
            rexmpp_log(comp->s, LOG_DEBUG,
                       "RTCP SR received: SSRC % " PRIx32 ", NTP TS %" PRIu64
                       ", RTP TS %" PRIu32 ", PC %" PRIu32 ", OC %" PRIu32,
                       rtcp_ssrc, rtcp_ntp_timestamp, rtcp_rtp_timestamp,
                       rtcp_packet_count, rtcp_octet_count);
            pos = 28;
          } else if (packet_type == 201 && len >= 8) {
            uint32_t rtcp_ssrc =
              (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
            rexmpp_log(comp->s, LOG_DEBUG,
                       "RTCP RR received: SSRC %x",
                       rtcp_ssrc);
            pos = 8;
          } else {
            rexmpp_log(comp->s, LOG_DEBUG, "RTCP packet received, PT %d",
                       packet_type);
          }

          while ((pos > 0)
                 && ((pos + 24) <= len)
                 && ((pos + 24) <= (rtcp_len + 1) * 4)) {
            uint32_t rtcp_ssrc = (buf[pos] << 24) | (buf[pos + 1] << 16)
              | (buf[pos + 2] << 8) | buf[pos + 3];
            uint8_t fraction_lost = buf[pos + 4];
            uint32_t packets_lost =
              (buf[pos + 5] << 24) | (buf[pos + 6] << 16) | buf[pos + 7];
            uint32_t rtcp_ehsn = (buf[pos + 8] << 24) | (buf[pos + 9] << 16)
              | (buf[pos + 10] << 8) | buf[pos + 11];
            uint32_t rtcp_jitter = (buf[pos + 12] << 24) | (buf[pos + 13] << 16)
              | (buf[pos + 14] << 8) | buf[pos + 15];
            uint32_t rtcp_lsr = (buf[pos + 16] << 24) | (buf[pos + 17] << 16)
              | (buf[pos + 18] << 8) | buf[pos + 19];
            uint32_t rtcp_dlsr = (buf[pos + 20] << 24) | (buf[pos + 21] << 16)
              | (buf[pos + 22] << 8) | buf[pos + 23];
            rexmpp_log(comp->s, LOG_DEBUG,
                       "RTCP report block: SSRC % " PRIx32 ", lost %" PRIu32
                       "%, %" PRIu8 " packets, "
                       "highest seq num %" PRIu32
                       ", jitter %" PRIu32 ", LSR %" PRIu32 ", DLSR %" PRIu32,
                       rtcp_ssrc, fraction_lost, packets_lost,
                       rtcp_ehsn, rtcp_jitter, rtcp_lsr, rtcp_dlsr);
            pos += 24;
          }
        }
      } else {
        rexmpp_log(comp->s, LOG_WARNING,
                   "Unhandled RT(C)P packet: version %d, length %d",
                   version, len);
      }
    }
  } else {
    if (comp->dtls->dtls_buf_len + len < DTLS_SRTP_BUF_SIZE) {
      memcpy(comp->dtls->dtls_buf + comp->dtls->dtls_buf_len, buf, len);
      comp->dtls->dtls_buf_len += len;
    } else {
      rexmpp_log(comp->s, LOG_WARNING, "Dropping a DTLS packet");
    }
  }
}

int
rexmpp_jingle_ice_agent_init (rexmpp_jingle_session_t *sess)
{
  sess->ice_agent = nice_agent_new(g_main_loop_get_context (sess->s->jingle->gloop),
                                   NICE_COMPATIBILITY_RFC5245);
  if (sess->s->local_address != NULL) {
    NiceAddress *address = nice_address_new();
    nice_address_set_from_string(address, sess->s->local_address);
    nice_agent_add_local_address(sess->ice_agent, address);
    nice_address_free(address);
  }
  g_object_set(sess->ice_agent, "controlling-mode", sess->initiator, NULL);
  g_signal_connect(sess->ice_agent, "candidate-gathering-done",
                   G_CALLBACK(rexmpp_jingle_candidate_gathering_done_cb), sess);
  g_signal_connect(sess->ice_agent, "component-state-changed",
                   G_CALLBACK(rexmpp_jingle_component_state_changed_cb), sess);

  sess->ice_stream_id = nice_agent_add_stream(sess->ice_agent, sess->rtcp_mux ? 1 : 2);
  if (sess->ice_stream_id == 0) {
    rexmpp_log(sess->s, LOG_ERR, "Failed to add an ICE agent stream");
    g_object_unref(sess->ice_agent);
    sess->ice_agent = NULL;
    return 0;
  }

  int i;
  for (i = 0; i < (sess->rtcp_mux ? 1 : 2); i++) {
    nice_agent_attach_recv(sess->ice_agent, sess->ice_stream_id, i + 1,
                           g_main_loop_get_context (sess->s->jingle->gloop),
                           rexmpp_jingle_ice_recv_cb,
                           &sess->component[i]);
  }

  return 1;
}

void rexmpp_jingle_turn_dns_cb (rexmpp_t *s, void *ptr, rexmpp_dns_result_t *result) {
  rexmpp_jingle_session_t *sess = ptr;
  if (result != NULL && result->data != NULL) {
    /* Only using the first address. */
    struct in_addr addr;
    memcpy(&addr,
           result->data[0],
           result->len[0]);
    char *ip = inet_ntoa(addr);
    rexmpp_log(s, LOG_DEBUG, "Resolved TURN server's hostname to %s (%ssecure)",
               ip, result->secure ? "" : "in");
    /* Adding it just for the first component for now. */
    nice_agent_set_relay_info(sess->ice_agent, sess->ice_stream_id, 1,
                              ip, sess->turn_port,
                              sess->turn_username, sess->turn_password,
                              NICE_RELAY_TYPE_TURN_UDP);
  } else {
    rexmpp_log(s, LOG_WARNING, "Failed to resolve TURN server's address");
  }
  nice_agent_gather_candidates(sess->ice_agent, sess->ice_stream_id);
  rexmpp_dns_result_free(result);
}

void rexmpp_jingle_stun_dns_cb (rexmpp_t *s, void *ptr, rexmpp_dns_result_t *result) {
  rexmpp_jingle_session_t *sess = ptr;
  if (result != NULL && result->data != NULL) {
    /* Only using the first address. */
    struct in_addr addr;
    memcpy(&addr,
           result->data[0],
           result->len[0]);
    char *ip = inet_ntoa(addr);
    rexmpp_log(s, LOG_DEBUG, "Resolved STUN server's hostname to %s (%ssecure)",
               ip, result->secure ? "" : "in");
    g_object_set(sess->ice_agent, "stun-server", ip, NULL);
    g_object_set(sess->ice_agent, "stun-server-port", sess->stun_port, NULL);
  } else {
    rexmpp_log(s, LOG_WARNING, "Failed to resolve STUN server's address");
  }

  /* Proceed to TURN resolution if there's a TURN host, or just start
     connecting. */
  if (sess->turn_host != NULL) {
    rexmpp_dns_resolve(s, sess->turn_host, 1, 1, sess, rexmpp_jingle_turn_dns_cb);
  } else {
    nice_agent_gather_candidates(sess->ice_agent, sess->ice_stream_id);
  }
  rexmpp_dns_result_free(result);
}

void rexmpp_jingle_turn_cb (rexmpp_t *s,
                            void *sess_ptr,
                            rexmpp_xml_t *req,
                            rexmpp_xml_t *response,
                            int success)
{
  (void)req;
  rexmpp_jingle_session_t *sess = sess_ptr;
  if (success) {
    /* use credentials */
    rexmpp_xml_t *services = rexmpp_xml_first_elem_child(response);
    if (rexmpp_xml_match(services, "urn:xmpp:extdisco:2", "services")) {
      rexmpp_xml_t *service = rexmpp_xml_first_elem_child(services);
      while (service != NULL) {
        if (rexmpp_xml_match(service, "urn:xmpp:extdisco:2", "service")) {
          const char *type = rexmpp_xml_find_attr_val(service, "type");
          const char *transport = rexmpp_xml_find_attr_val(service, "transport");
          const char *host = rexmpp_xml_find_attr_val(service, "host");
          const char *port = rexmpp_xml_find_attr_val(service, "port");
          const char *username = rexmpp_xml_find_attr_val(service, "username");
          const char *password = rexmpp_xml_find_attr_val(service, "password");

          if (sess->stun_host == NULL &&
              type != NULL && transport != NULL && host != NULL && port != NULL &&
              strcmp(type, "stun") == 0 && strcmp(transport, "udp") == 0) {
            sess->stun_host = strdup(host);
            sess->stun_port = atoi(port);
            rexmpp_log(s, LOG_DEBUG, "Setting STUN server to %s:%s", host, port);
          }

          if (sess->turn_host == NULL &&
              type != NULL && transport != NULL && host != NULL && port != NULL &&
              username != NULL && password != NULL &&
              strcmp(type, "turn") == 0 && strcmp(transport, "udp") == 0) {
            sess->turn_host = strdup(host);
            sess->turn_port = atoi(port);
            sess->turn_username = strdup(username);
            sess->turn_password = strdup(password);
            rexmpp_log(s, LOG_DEBUG, "Setting TURN server to %s:%s", host, port);
          }
        }
        service = rexmpp_xml_next_elem_sibling(service);
      }
      if (sess->stun_host != NULL) {
        /* Resolve, then resolve STUN host, then connect. */
        rexmpp_dns_resolve(s, sess->turn_host, 1, 1, sess, rexmpp_jingle_stun_dns_cb);
        return;
      } else if (sess->stun_host != NULL) {
        /* Resolve, then connect. */
        /* todo: handle IPv6 too, but that's awkward enough for now to
           deal with resolution before calling the library. And
           hopefully IPv6 will make all this NAT traversal business
           unnecessary anyway. */
        rexmpp_dns_resolve(s, sess->stun_host, 1, 1, sess, rexmpp_jingle_turn_dns_cb);
        return;
      } else {
        rexmpp_log(s, LOG_DEBUG, "No STUN or TURN servers found");
      }
    }
  } else {
    rexmpp_log(s, LOG_DEBUG,
               "Failed to request TURN credentials, "
               "trying to connect without STUN/TURN");
  }
  nice_agent_gather_candidates(sess->ice_agent, sess->ice_stream_id);
}

void rexmpp_jingle_discover_turn_cb (rexmpp_t *s,
                                     void *sess_ptr,
                                     rexmpp_xml_t *req,
                                     rexmpp_xml_t *response,
                                     int success)
{
  (void)req;
  const char *response_from = rexmpp_xml_find_attr_val(response, "from");
  rexmpp_jingle_session_t *sess = sess_ptr;
  if (success) {
    rexmpp_xml_t *services =
      rexmpp_xml_new_elem("services", "urn:xmpp:extdisco:2");
    rexmpp_xml_add_attr(services, "type", "turn");
    rexmpp_iq_new(s, "get", response_from, services,
                  rexmpp_jingle_turn_cb, sess_ptr);
  } else {
    rexmpp_log(s, LOG_DEBUG,
               "No external service discovery, trying to connect without STUN/TURN");
    nice_agent_gather_candidates(sess->ice_agent, sess->ice_stream_id);
  }
}

void rexmpp_jingle_discover_turn (rexmpp_t *s, rexmpp_jingle_session_t *sess) {
  rexmpp_disco_find_feature(s, s->initial_jid.domain, "urn:xmpp:extdisco:2",
                            rexmpp_jingle_discover_turn_cb, sess, 0, 1);
}

rexmpp_err_t
rexmpp_jingle_call (rexmpp_t *s,
                    const char *jid)
{
  rexmpp_jingle_session_t *sess =
    rexmpp_jingle_session_create(s, strdup(jid), rexmpp_gen_id(s),
                                 REXMPP_JINGLE_SESSION_MEDIA, 1);
  rexmpp_jingle_ice_agent_init(sess);
  rexmpp_jingle_discover_turn(s, sess);
  return REXMPP_SUCCESS;
}

rexmpp_err_t
rexmpp_jingle_call_accept (rexmpp_t *s,
                           const char *sid)
{
  rexmpp_jingle_session_t *sess = rexmpp_jingle_session_by_id(s, sid);
  if (sess == NULL) {
    return REXMPP_E_OTHER;
  }
  rexmpp_jingle_ice_agent_init(sess);

  rexmpp_xml_t *content =
    rexmpp_xml_find_child(sess->initiate,
                          "urn:xmpp:jingle:1",
                          "content");
  rexmpp_xml_t * ice_udp_transport =
    rexmpp_xml_find_child(content,
                          "urn:xmpp:jingle:transports:ice-udp:1",
                          "transport");
  if (ice_udp_transport == NULL) {
    rexmpp_log(s, LOG_ERR, "No ICE-UDP transport defined for session %s", sid);
    rexmpp_jingle_session_terminate
      (s, sid,
       rexmpp_xml_new_elem("unsupported-transports", "urn:xmpp:jingle:1"),
       "No ICE-UDP transport defined");
    return REXMPP_E_OTHER;
  }
  rexmpp_jingle_ice_udp_add_remote(sess, ice_udp_transport);
  rexmpp_jingle_discover_turn(s, sess);
  return REXMPP_SUCCESS;
}
#else  /* ENABLE_CALLS */

rexmpp_err_t
rexmpp_jingle_call (rexmpp_t *s,
                    const char *jid)
{
  (void)jid;
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without support for media calls");
  return REXMPP_E_OTHER;
}

rexmpp_err_t
rexmpp_jingle_call_accept (rexmpp_t *s,
                           const char *sid)
{
  (void)sid;
  rexmpp_log(s, LOG_ERR, "rexmpp is compiled without support for media calls");
  return REXMPP_E_OTHER;
}
#endif  /* ENABLE_CALLS */

int rexmpp_jingle_iq (rexmpp_t *s, rexmpp_xml_t *elem) {
  int handled = 0;
  if (! s->enable_jingle) {
    return handled;
  }
  rexmpp_xml_t *jingle =
    rexmpp_xml_find_child(elem, "urn:xmpp:jingle:1", "jingle");
  if (jingle != NULL) {
    handled = 1;
    const char *action = rexmpp_xml_find_attr_val(jingle, "action");
    const char *sid = rexmpp_xml_find_attr_val(jingle, "sid");
    const char *from_jid = rexmpp_xml_find_attr_val(elem, "from");
    if (action != NULL && sid != NULL && from_jid != NULL) {
      if (strcmp(action, "session-initiate") == 0) {
        /* todo: could be more than one content element, handle that */
        rexmpp_xml_t *content =
          rexmpp_xml_find_child(jingle, "urn:xmpp:jingle:1", "content");
        if (content == NULL) {
          rexmpp_iq_reply(s, elem, "error",
                          rexmpp_xml_error("cancel", "bad-request"));
        } else {
          rexmpp_iq_reply(s, elem, "result", NULL);

          rexmpp_xml_t *file_description =
            rexmpp_xml_find_child(content, "urn:xmpp:jingle:apps:file-transfer:5",
                                  "description");
          rexmpp_xml_t *ibb_transport =
            rexmpp_xml_find_child(content, "urn:xmpp:jingle:transports:ibb:1",
                                  "transport");
          rexmpp_xml_t *ice_udp_transport =
            rexmpp_xml_find_child(content, "urn:xmpp:jingle:transports:ice-udp:1",
                                  "transport");
          rexmpp_xml_t *rtp_description =
            rexmpp_xml_find_child(content, "urn:xmpp:jingle:apps:rtp:1",
                                  "description");

          if (file_description != NULL && ibb_transport != NULL) {
            const char *ibb_sid = rexmpp_xml_find_attr_val(ibb_transport, "sid");
            if (ibb_sid != NULL) {
              rexmpp_log(s, LOG_DEBUG,
                         "Jingle session-initiate from %s, sid %s, ibb sid %s",
                         from_jid, sid, ibb_sid);
              rexmpp_jingle_session_t *sess =
                rexmpp_jingle_session_create(s, strdup(from_jid), strdup(sid),
                                             REXMPP_JINGLE_SESSION_FILE, 0);
              if (sess != NULL) {
                sess->initiate = rexmpp_xml_clone(jingle);
                sess->ibb_sid = strdup(ibb_sid);
              } else {
                rexmpp_jingle_session_terminate
                  (s, sid,
                   rexmpp_xml_new_elem("failed-transport",
                                       "urn:xmpp:jingle:1"),
                   NULL);
              }
            } else {
              rexmpp_log(s, LOG_ERR,
                         "Jingle IBB transport doesn't have a sid attribute");
              rexmpp_jingle_session_terminate
                (s, sid,
                 rexmpp_xml_new_elem("unsupported-transports",
                                     "urn:xmpp:jingle:1"),
                 NULL);
            }
#ifdef ENABLE_CALLS
          } else if (ice_udp_transport != NULL && rtp_description != NULL) {
            rexmpp_log(s, LOG_DEBUG, "Jingle session-initiate from %s, sid %s",
                       from_jid, sid);
            rexmpp_jingle_session_t *sess =
              rexmpp_jingle_session_create(s, strdup(from_jid), strdup(sid),
                                           REXMPP_JINGLE_SESSION_MEDIA, 0);
            sess->rtcp_mux =
              (rexmpp_xml_find_child(rtp_description,
                                     "urn:xmpp:jingle:apps:rtp:1",
                                     "rtcp-mux") != NULL);
            sess->initiate = rexmpp_xml_clone(jingle);
#endif  /* ENABLE_CALLS */
          } else if (file_description == NULL &&
                     rtp_description == NULL) {
            rexmpp_jingle_session_terminate
              (s, sid,
               rexmpp_xml_new_elem("unsupported-applications",
                                   "urn:xmpp:jingle:1"),
               NULL);
          } else if (ibb_transport == NULL &&
                     ice_udp_transport == NULL) {
            rexmpp_jingle_session_terminate
              (s, sid,
               rexmpp_xml_new_elem("unsupported-transports",
                                   "urn:xmpp:jingle:1"),
               NULL);
          } else {
            /* todo: some other error */
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
          session->accept = rexmpp_xml_clone(jingle);
          rexmpp_xml_t *content =
            rexmpp_xml_find_child(jingle, "urn:xmpp:jingle:1", "content");
          rexmpp_xml_t *file_description =
            rexmpp_xml_find_child(content, "urn:xmpp:jingle:apps:file-transfer:5",
                                  "description");
          rexmpp_xml_t *ibb_transport =
            rexmpp_xml_find_child(content, "urn:xmpp:jingle:transports:ibb:1",
                                  "transport");
          if (ibb_transport != NULL && file_description != NULL) {
            rexmpp_xml_t *open =
              rexmpp_xml_new_elem("open", "http://jabber.org/protocol/ibb");
            rexmpp_xml_add_attr(open, "sid", session->ibb_sid);
            rexmpp_xml_add_attr(open, "block-size", "4096");
            rexmpp_xml_add_attr(open, "stanza", "iq");
            rexmpp_iq_new(s, "set", session->jid, open,
                          rexmpp_jingle_ibb_send_cb, strdup(sid));
          } else {
#ifdef ENABLE_CALLS
            rexmpp_jingle_session_configure_audio(session);
            rexmpp_jingle_run_audio(session);
            rexmpp_xml_t *ice_udp_transport =
              rexmpp_xml_find_child(content, "urn:xmpp:jingle:transports:ice-udp:1",
                                    "transport");
            if (ice_udp_transport != NULL) {
              rexmpp_jingle_ice_udp_add_remote(session, ice_udp_transport);
            } else {
              rexmpp_log(s, LOG_WARNING,
                         "ICE-UDP transport is unset in session-accept");
            }
#endif  /* ENABLE_CALLS */
          }
        } else {
          rexmpp_log(s, LOG_WARNING, "Jingle session %s is not found", sid);
        }
      } else if (strcmp(action, "transport-info") == 0) {
        rexmpp_iq_reply(s, elem, "result", NULL);
        rexmpp_jingle_session_t *session = rexmpp_jingle_session_by_id(s, sid);
        if (session != NULL) {
#ifdef ENABLE_CALLS
          rexmpp_xml_t *content =
            rexmpp_xml_find_child(jingle, "urn:xmpp:jingle:1", "content");
          rexmpp_xml_t *ice_udp_transport =
            rexmpp_xml_find_child(content, "urn:xmpp:jingle:transports:ice-udp:1",
                                  "transport");
          if (ice_udp_transport != NULL) {
            rexmpp_jingle_ice_udp_add_remote(session, ice_udp_transport);
          }
#endif  /* ENABLE_CALLS */
        }
      } else {
        rexmpp_log(s, LOG_WARNING, "Unknown Jingle action: %s", action);
        rexmpp_iq_reply(s, elem, "error",
                        rexmpp_xml_error("cancel", "bad-request"));
      }
    } else {
      rexmpp_log(s, LOG_WARNING, "Received a malformed Jingle element");
      rexmpp_iq_reply(s, elem, "error",
                      rexmpp_xml_error("cancel", "bad-request"));
    }
  }

  /* XEP-0261: Jingle In-Band Bytestreams Transport Method */
  rexmpp_xml_t *ibb_open =
    rexmpp_xml_find_child(elem, "http://jabber.org/protocol/ibb", "open");
  if (ibb_open != NULL) {
    handled = 1;
    /* no-op, though could check sid here. */
    rexmpp_iq_reply(s, elem, "result", NULL);
  }
  rexmpp_xml_t *ibb_close =
    rexmpp_xml_find_child(elem, "http://jabber.org/protocol/ibb", "close");
  if (ibb_close != NULL) {
    handled = 1;
    rexmpp_iq_reply(s, elem, "result", NULL);
    const char *sid = rexmpp_xml_find_attr_val(ibb_close, "sid");
    
    if (sid != NULL) {
      rexmpp_jingle_session_t *session = rexmpp_jingle_session_by_ibb_sid(s, sid);
      if (session != NULL) {
        rexmpp_jingle_session_terminate
          (s, session->sid,
           rexmpp_xml_new_elem("success", "urn:xmpp:jingle:1"), NULL);
      }
    }
  }
  rexmpp_xml_t *ibb_data =
    rexmpp_xml_find_child(elem, "http://jabber.org/protocol/ibb", "data");
  if (ibb_data != NULL) {
    handled = 1;
    const char *sid = rexmpp_xml_find_attr_val(ibb_data, "sid");
    if (sid != NULL) {
      rexmpp_jingle_session_t *session = rexmpp_jingle_session_by_ibb_sid(s, sid);
      if (session != NULL && session->ibb_fh != NULL) {
        char *data = NULL;
        const char *data_base64 = rexmpp_xml_text_child(ibb_data);
        if (data_base64 != NULL) {
          size_t data_len = 0;
          int base64_err = rexmpp_base64_from(data_base64, strlen(data_base64),
                                              &data, &data_len);
          if (base64_err != 0) {
            rexmpp_log(s, LOG_ERR, "Base-64 decoding failure");
          } else {
            size_t written = fwrite(data, 1, data_len, session->ibb_fh);
            if (written != data_len) {
              rexmpp_log(s, LOG_ERR, "Wrote %d bytes, expected %d",
                         written, data_len);
              /* todo: maybe introduce buffering, or make it an error */
            }
          }
        }
      }
    }
    /* todo: report errors */
    rexmpp_iq_reply(s, elem, "result", NULL);
  }
  return handled;
}

int rexmpp_jingle_fds(rexmpp_t *s, fd_set *read_fds, fd_set *write_fds) {
  int nfds = -1;
#ifdef ENABLE_CALLS
  gint poll_timeout;
  GPollFD poll_fds[10];
  GMainContext* gctx = g_main_loop_get_context(s->jingle->gloop);
  if (g_main_context_acquire(gctx)) {
    gint poll_fds_n = g_main_context_query(gctx,
                                           G_PRIORITY_HIGH,
                                           &poll_timeout,
                                           (GPollFD *)&poll_fds,
                                           10);
    g_main_context_release(gctx);
    int i;
    for (i = 0; i < poll_fds_n; i++) {
      if (poll_fds[i].events & (G_IO_IN | G_IO_HUP | G_IO_ERR)) {
        FD_SET(poll_fds[i].fd, read_fds);
      }
      if (poll_fds[i].events & (G_IO_OUT | G_IO_ERR)) {
        FD_SET(poll_fds[i].fd, write_fds);
      }
      if (poll_fds[i].fd > nfds) {
        nfds = poll_fds[i].fd;
      }
    }

    rexmpp_jingle_session_t *sess;
    for (sess = s->jingle->sessions; sess != NULL; sess = sess->next) {
      for (i = 0; i < 2; i++) {
        if (sess->component[i].dtls_state != REXMPP_TLS_INACTIVE &&
            sess->component[i].dtls_state != REXMPP_TLS_CLOSED &&
            sess->component[i].dtls_state != REXMPP_TLS_ERROR) {
          GPtrArray *sockets =
            nice_agent_get_sockets(sess->ice_agent,
                                   sess->ice_stream_id, i + 1);
          guint i;
          for (i = 0; i < sockets->len; i++) {
            int fd = g_socket_get_fd(sockets->pdata[i]);
            FD_SET(fd, read_fds);
            if (fd > nfds) {
              nfds = fd;
            }
          }
          g_ptr_array_unref(sockets);
        }
      }
    }
  } else {
    rexmpp_log(s, LOG_ERR,
               "Failed to acquire GMainContext in rexmpp_jingle_fds");
  }
#else  /* ENABLE_CALLS */
  (void)s;
  (void)read_fds;
  (void)write_fds;
#endif  /* ENABLE_CALLS */
  return (nfds + 1);
}

struct timespec * rexmpp_jingle_timeout (rexmpp_t *s,
                                         struct timespec *max_tv,
                                         struct timespec *tv) {
#ifdef ENABLE_CALLS
  gint poll_timeout;
  GPollFD poll_fds[10];
  GMainContext* gctx = g_main_loop_get_context(s->jingle->gloop);
  if (g_main_context_acquire(gctx)) {
    g_main_context_query(gctx,
                         G_PRIORITY_HIGH,
                         &poll_timeout,
                         (GPollFD *)&poll_fds,
                         10);
    g_main_context_release(gctx);

    rexmpp_jingle_session_t *sess;
    for (sess = s->jingle->sessions; sess != NULL; sess = sess->next) {
      int i;
      for (i = 0; i < 2; i++) {
        if (sess->component[i].dtls_state != REXMPP_TLS_INACTIVE &&
            sess->component[i].dtls_state != REXMPP_TLS_CLOSED &&
            sess->component[i].dtls_state != REXMPP_TLS_ERROR) {
          int tms = rexmpp_dtls_timeout(sess->s, sess->component[i].dtls);
          if (tms > 0 && (poll_timeout < 0 || tms < poll_timeout)) {
            poll_timeout = tms;
          }
          /* Set poll timeout to at most 5 ms if there are connected
             components, for timely transmission of Jingle data. */
          if (sess->component[i].dtls_state == REXMPP_TLS_ACTIVE &&
              (poll_timeout < 0 || poll_timeout > 5)) {
            poll_timeout = 5;
          }
        }
      }
    }

    if (poll_timeout >= 0) {
      int sec = poll_timeout / 1000;
      int nsec = (poll_timeout % 1000) * 1000000;
      if (max_tv == NULL ||
          (max_tv->tv_sec > sec ||
           (max_tv->tv_sec == sec && max_tv->tv_nsec > nsec))) {
        tv->tv_sec = sec;
        tv->tv_nsec = nsec;
        max_tv = tv;
      }
    }
  } else {
    rexmpp_log(s, LOG_ERR,
               "Failed to acquire GMainContext in rexmpp_jingle_timeout");
  }
#else  /* ENABLE_CALLS */
  (void)s;
  (void)tv;
#endif  /* ENABLE_CALLS */
  return max_tv;
}

rexmpp_err_t
rexmpp_jingle_run (rexmpp_t *s,
                   fd_set *read_fds,
                   fd_set *write_fds)
{
  (void)write_fds;
  (void)read_fds;
#ifdef ENABLE_CALLS
  rexmpp_jingle_session_t *sess;
  int err;
  unsigned char client_sess_key[SRTP_AES_ICM_128_KEY_LEN_WSALT * 2],
    server_sess_key[SRTP_AES_ICM_128_KEY_LEN_WSALT * 2];
  for (sess = s->jingle->sessions; sess != NULL; sess = sess->next) {
    char input[4096 + SRTP_MAX_TRAILER_LEN];
    int input_len;
    int comp_id;

    for (comp_id = 0; comp_id < 2; comp_id++) {
      rexmpp_jingle_component_t *comp = &sess->component[comp_id];

      if (comp->dtls_state == REXMPP_TLS_HANDSHAKE) {
        int ret = rexmpp_tls_handshake(s, comp->dtls);
        if (ret == REXMPP_TLS_SUCCESS) {
          rexmpp_log(s, LOG_DEBUG,
                     "DTLS connected for Jingle session %s, component %d",
                     sess->sid, comp->component_id);
          comp->dtls_state = REXMPP_TLS_ACTIVE;

          rexmpp_xml_t *jingle = comp->session->initiator
            ? comp->session->accept
            : comp->session->initiate;
          rexmpp_xml_t *fingerprint =
            rexmpp_xml_find_child
            (rexmpp_xml_find_child
             (rexmpp_xml_find_child
              (jingle, "urn:xmpp:jingle:1", "content"),
              "urn:xmpp:jingle:transports:ice-udp:1", "transport"),
             "urn:xmpp:jingle:apps:dtls:0", "fingerprint");
          if (fingerprint == NULL) {
            /* todo: might be neater to check it upon receiving the
               stanzas, instead of checking it here */
            rexmpp_log(comp->s, LOG_ERR,
                       "No fingerprint in the peer's Jingle element");
            rexmpp_jingle_session_terminate
              (s, sess->sid,
               rexmpp_xml_new_elem("connectivity-error", "urn:xmpp:jingle:1"),
               "No fingerprint element");
            return REXMPP_E_TLS;
          } else {
            const char *hash_str = rexmpp_xml_find_attr_val(fingerprint, "hash");
            if (hash_str == NULL) {
              rexmpp_log(comp->s, LOG_ERR,
                         "No hash attribute in the peer's fingerprint element");
              rexmpp_jingle_session_terminate
                (s, sess->sid,
                 rexmpp_xml_new_elem("connectivity-error", "urn:xmpp:jingle:1"),
                 "No hash attribute in the fingerprint element");
              return REXMPP_E_TLS;
            } else {
              char fp[64], fp_str[64 * 3];
              size_t fp_size = 64;
              if (rexmpp_tls_peer_fp(comp->s, comp->dtls, hash_str,
                                     fp, fp_str, &fp_size))
                {
                  rexmpp_jingle_session_terminate
                    (s, sess->sid,
                     rexmpp_xml_new_elem("connectivity-error",
                                         "urn:xmpp:jingle:1"),
                     "Failed to obtain the DTLS certificate fingerprint");
                  return REXMPP_E_TLS;
                } else {
                const char *fingerprint_cont =
                  rexmpp_xml_text_child(fingerprint);
                /* Fingerprint string should be uppercase, but
                   allowing any case for now, while Dino uses
                   lowercase. */
                int fingerprint_mismatch = strcasecmp(fingerprint_cont, fp_str);
                if (fingerprint_mismatch) {
                  rexmpp_log(comp->s, LOG_ERR,
                             "Peer's fingerprint mismatch: expected %s,"
                             " calculated %s",
                             fingerprint_cont, fp_str);
                  rexmpp_jingle_session_terminate
                    (s, sess->sid,
                     rexmpp_xml_new_elem("security-error", "urn:xmpp:jingle:1"),
                     "DTLS certificate fingerprint mismatch");
                  return REXMPP_E_TLS;
                } else {
                  /* The fingerprint is fine, proceed to SRTP. */
                  rexmpp_log(comp->s, LOG_DEBUG,
                             "Peer's fingerprint: %s", fp_str);

                  rexmpp_tls_srtp_get_keys(s, comp->dtls,
                                           SRTP_AES_128_KEY_LEN, SRTP_SALT_LEN,
                                           client_sess_key, server_sess_key);

                  int active_role = rexmpp_jingle_dtls_is_active(sess, 0);

                  srtp_policy_t inbound;
                  memset(&inbound, 0x0, sizeof(srtp_policy_t));
                  srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&inbound.rtp);
                  srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&inbound.rtcp);
                  inbound.ssrc.type = ssrc_any_inbound;
                  inbound.key = active_role ? server_sess_key : client_sess_key;
                  inbound.window_size = 1024;
                  inbound.allow_repeat_tx = 1;
                  inbound.next = NULL;
                  err = srtp_create(&(comp->srtp_in), &inbound);
                  if (err) {
                    rexmpp_log(s, LOG_ERR, "Failed to create srtp_in");
                  }

                  srtp_policy_t outbound;
                  memset(&outbound, 0x0, sizeof(srtp_policy_t));
                  srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&outbound.rtp);
                  srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&outbound.rtcp);
                  outbound.ssrc.type = ssrc_any_outbound;
                  outbound.key = active_role ? client_sess_key : server_sess_key;
                  outbound.window_size = 1024;
                  outbound.allow_repeat_tx = 1;
                  outbound.next = NULL;
                  err = srtp_create(&(comp->srtp_out), &outbound);
                  if (err) {
                    rexmpp_log(s, LOG_ERR, "Failed to create srtp_out");
                  }
                }
              }
            }
          }
        } else if (ret != REXMPP_TLS_E_AGAIN) {
          rexmpp_log(s, LOG_ERR, "DTLS error for session %s, component %d",
                     sess->sid, comp->component_id);
          comp->dtls_state = REXMPP_TLS_ERROR;
          if (comp->component_id == 1) {
            rexmpp_jingle_session_terminate
              (s, sess->sid,
               rexmpp_xml_new_elem("connectivity-error", "urn:xmpp:jingle:1"),
               "DTLS connection error");
            return REXMPP_E_TLS;
          }
        }
      }

      /* Check on the DTLS session, too. */
      if (comp->dtls_state == REXMPP_TLS_ACTIVE) {
        ssize_t received;
        rexmpp_tls_recv(s, comp->dtls, input, 4096, &received);
      }
    }

    /* Send captured audio frames for established sessions. */
    if ((sess->component[0].dtls_state == REXMPP_TLS_ACTIVE)
        && (sess->component[0].srtp_out != NULL)
        && (sess->codec != REXMPP_CODEC_UNDEFINED)) {
      struct ring_buf *capture = &(sess->ring_buffers.capture);
      while (capture->write_pos != capture->read_pos) {
        if (sess->codec == REXMPP_CODEC_PCMU) {
          for (input_len = 12;
               input_len < 4096 && capture->write_pos != capture->read_pos;
               input_len++)
            {
              input[input_len] =
                rexmpp_pcmu_encode(capture->buf[capture->read_pos]);
              capture->read_pos++;
              capture->read_pos %= PA_BUF_SIZE;
              sess->rtp_timestamp++;
            }
        } else if (sess->codec == REXMPP_CODEC_PCMA) {
          for (input_len = 12;
               input_len < 4096 && capture->write_pos != capture->read_pos;
               input_len++)
            {
              input[input_len] =
                rexmpp_pcma_encode(capture->buf[capture->read_pos]);
              capture->read_pos++;
              capture->read_pos %= PA_BUF_SIZE;
              sess->rtp_timestamp++;
            }
        }
#ifdef HAVE_OPUS
        else if (sess->codec == REXMPP_CODEC_OPUS) {
          unsigned int samples_available;
          if (capture->write_pos > capture->read_pos) {
            samples_available = capture->write_pos - capture->read_pos;
          } else {
            samples_available =
              (PA_BUF_SIZE - capture->read_pos) + capture->write_pos;
          }
          unsigned int frame_size = 480;
          if (samples_available >= frame_size * 2) {
            opus_int16 pcm[4096];
            /* Prepare a regular buffer */
            unsigned int i;
            for (i = 0;
                 (i < frame_size * 2) &&
                   (capture->write_pos != capture->read_pos);
                 i++)
              {
                pcm[i] = capture->buf[capture->read_pos];
                capture->read_pos++;
                capture->read_pos %= PA_BUF_SIZE;
                sess->rtp_timestamp++;
              }
            /* Encode it */
            int encoded_len;
            encoded_len = opus_encode(sess->opus_enc,
                                      pcm,
                                      frame_size,
                                      (unsigned char*)input + 12,
                                      4096);
            if (encoded_len < 0) {
              rexmpp_log(s, LOG_ERR, "Failed to encode an Opus frame");
              break;
            }
            input_len = 12 + encoded_len;
          } else {
            break;
          }
        }
#endif  /* HAVE_OPUS */

        /* Setup an RTP header */
        uint32_t hl, nl;
        hl = (2 << 30)                /* version */
          | (0 << 29)                 /* padding */
          | (0 << 28)                 /* extension */
          | (0 << 24)                 /* CSRC count */
          | (0 << 23)                 /* marker */
          | (sess->payload_type << 16)  /* paylaod type, RFC 3551 */
          | sess->rtp_seq_num;
        sess->rtp_seq_num++;
        nl = htonl(hl);
        memcpy(input, &nl, sizeof(uint32_t));
        nl = htonl(sess->rtp_timestamp);
        memcpy(input + 4, &nl, sizeof(uint32_t));
        nl = htonl(sess->rtp_ssrc);
        memcpy(input + 8, &nl, sizeof(uint32_t));
        /* The RTP header is ready */

        srtp_ctx_t *srtp_out = sess->component[0].srtp_out;
        err = srtp_protect(srtp_out, input, &input_len);
        if (err) {
          rexmpp_log(s, LOG_ERR, "SRTP protect error %d", err);
        } else {
          nice_agent_send(sess->ice_agent, sess->ice_stream_id,
                          /* sess->rtcp_mux ? 1 : comp->component_id, */
                          1,
                          input_len, input);
        }
      }
    }
  }
  g_main_context_iteration(g_main_loop_get_context(s->jingle->gloop), 0);
#else  /* ENABLE_CALLS */
  (void)s;
  (void)read_fds;
#endif  /* ENABLE_CALLS */
  return REXMPP_SUCCESS;
}
