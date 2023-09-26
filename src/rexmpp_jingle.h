/**
   @file rexmpp_jingle.h
   @brief Jingle routines
   @author defanor <defanor@uberspace.net>
   @date 2021
   @copyright MIT license.

*/


#ifndef REXMPP_JINGLE_H
#define REXMPP_JINGLE_H

#include "config.h"

#ifdef ENABLE_CALLS
#include <glib.h>
#include <agent.h>
#include <srtp2/srtp.h>
#include "portaudio.h"
#ifdef HAVE_OPUS
#include <opus/opus.h>
#endif
#define PA_BUF_SIZE 0x4000
#endif

#include "rexmpp.h"
#include "rexmpp_tls.h"


/** @brief Processes incoming Jingle IQs. */
int rexmpp_jingle_iq (rexmpp_t *s, rexmpp_xml_t *elem);

/** @brief Destroys Jingle sessions. */
void rexmpp_jingle_stop (rexmpp_t *s);

/** @brief Accepts a file, given a sid and a path to save it to. */
rexmpp_err_t
rexmpp_jingle_accept_file_by_id (rexmpp_t *s,
                                 const char *sid,
                                 const char *path);

/** @brief Sends a file to a given full JID. */
rexmpp_err_t
rexmpp_jingle_send_file (rexmpp_t *s,
                         const char *jid,
                         char *path);

/** @brief Terminates a Jingle session. */
rexmpp_err_t
rexmpp_jingle_session_terminate (rexmpp_t *s,
                                 const char *sid,
                                 rexmpp_xml_t *reason_node,
                                 const char *reason_text);

typedef struct rexmpp_jingle_component rexmpp_jingle_component_t;
typedef struct rexmpp_jingle_session rexmpp_jingle_session_t;
typedef struct rexmpp_jingle_ctx rexmpp_jingle_ctx_t;

enum rexmpp_jingle_session_type {
  REXMPP_JINGLE_SESSION_FILE,
  REXMPP_JINGLE_SESSION_MEDIA
};

enum rexmpp_codec {
  REXMPP_CODEC_UNDEFINED,
  REXMPP_CODEC_PCMU,
  REXMPP_CODEC_PCMA,
  REXMPP_CODEC_OPUS
};

#ifdef ENABLE_CALLS
/* A structure used for callbacks, to pass rexmpp_t,
   rexmpp_jingle_session_t, and the component ID. */
struct rexmpp_jingle_component {
  rexmpp_t *s;
  rexmpp_jingle_session_t *session;
  int component_id;
  rexmpp_tls_t *dtls;
  enum tls_st dtls_state;
  srtp_t srtp_in;
  srtp_t srtp_out;
};

struct ring_buf
{
  int16_t buf[PA_BUF_SIZE];
  unsigned int write_pos;
  unsigned int read_pos;
};

struct pa_buffers
{
  struct ring_buf capture;
  struct ring_buf playback;
};
#endif

struct rexmpp_jingle_session {
  char *jid;
  char *sid;
  rexmpp_xml_t *initiate;
  rexmpp_xml_t *accept;
  rexmpp_jingle_session_t *next;
  /* Sessions are commonly passed to callbacks by external libraries,
     so it's convenient to have the corresponding rexmpp_t accessible
     through those. */
  rexmpp_t *s;
  int initiator;
  enum rexmpp_jingle_session_type type;

  /* IBB file transfers */
  FILE *ibb_fh;
  char *ibb_sid;
  uint16_t ibb_seq;

  /* ICE-UDP + DTLS-SRTP A/V calls */
#ifdef ENABLE_CALLS
  char *stun_host;
  uint16_t stun_port;
  char *turn_host;
  uint16_t turn_port;
  char *turn_username;
  char *turn_password;
  /* two component structures for callbacks: for SRTP and SRTCP */
  rexmpp_jingle_component_t component[2];
  int rtcp_mux;
  NiceAgent *ice_agent;
  int ice_stream_id;
  PaStream *pa_stream;
  /* The default codec and payload type for this stream. */
  enum rexmpp_codec codec;
  uint8_t payload_type;
  struct pa_buffers ring_buffers;
  uint16_t rtp_seq_num;
  uint16_t rtp_last_seq_num;
  uint32_t rtp_timestamp;
  uint32_t rtp_ssrc;
#ifdef HAVE_OPUS
  OpusEncoder *opus_enc;
  OpusDecoder *opus_dec;
#endif  /* HAVE_POUS */
#endif  /* ENABLE_CALLS */
};

struct rexmpp_jingle_ctx {
#ifdef ENABLE_CALLS
  GMainLoop* gloop;
#endif
  rexmpp_jingle_session_t *sessions;
};


int rexmpp_jingle_init (rexmpp_t *s);
rexmpp_err_t rexmpp_jingle_run (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds);
struct timespec * rexmpp_jingle_timeout (rexmpp_t *s,
                                         struct timespec *max_tv,
                                         struct timespec *tv);
int rexmpp_jingle_fds(rexmpp_t *s, fd_set *read_fds, fd_set *write_fds);

rexmpp_err_t
rexmpp_jingle_call (rexmpp_t *s,
                    const char *jid);
rexmpp_err_t
rexmpp_jingle_call_accept (rexmpp_t *s,
                           const char *sid);

#endif
