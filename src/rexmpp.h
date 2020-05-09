/**
   @file rexmpp.h
   @brief rexmpp, a reusable XMPP IM client library.
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#ifndef REXMPP_H
#define REXMPP_H

#include <ares.h>
#include <gnutls/gnutls.h>
#include <gsasl.h>
#include <libxml/tree.h>
#include "rexmpp_tcp.h"
#include "rexmpp_socks.h"


typedef struct rexmpp rexmpp_t;

/**
   @brief An info/query callback function type.
   @param[in,out] s A ::rexmpp structure.
   @param[in] request A request that was made.
   @param[in] response A response we have received. @c NULL if we are
   giving up on this IQ.

   A callback must not free the request or the response, but merely
   inspect those and react.
*/
typedef void (*rexmpp_iq_callback_t) (rexmpp_t *s,
                                      xmlNodePtr request,
                                      xmlNodePtr response,
                                      int success);

typedef struct rexmpp_iq rexmpp_iq_t;

/** @brief A pending info/query request. */
struct rexmpp_iq
{
  /** @brief The sent request. */
  xmlNodePtr request;
  /** @brief A callback to call on reply. */
  rexmpp_iq_callback_t cb;
  /** @brief Next pending IQ. */
  rexmpp_iq_t *next;
};


/** @brief DNS resolver state */
enum resolver_st {
  REXMPP_RESOLVER_NONE,
  REXMPP_RESOLVER_READY,
  REXMPP_RESOLVER_SRV,
  REXMPP_RESOLVER_SRV_2,
  REXMPP_RESOLVER_FAILURE
};

/** @brief TCP connection state */
enum tcp_st {
  /** No active TCP connection. */
  REXMPP_TCP_NONE,
  /** Connection establishment. */
  REXMPP_TCP_CONNECTING,
  /** Connected to a SOCKS server, asking it to connect to XMPP
      server. */
  REXMPP_TCP_SOCKS,
  /** Connected to XMPP server. */
  REXMPP_TCP_CONNECTED,
  /** Connection is closed properly. */
  REXMPP_TCP_CLOSED,
  /** Failed to connect. */
  REXMPP_TCP_CONNECTION_FAILURE,
  /** An error occurred. */
  REXMPP_TCP_ERROR
};

/** @brief High-level state of both XML streams */
enum stream_st {
  REXMPP_STREAM_NONE,
  /** Opening a stream: sending the opening tag, and waiting for
      one. */
  REXMPP_STREAM_OPENING,
  /** Stream futures negotiation. */
  REXMPP_STREAM_NEGOTIATION,
  /** STARTTLS negotiation. */
  REXMPP_STREAM_STARTTLS,
  /** SASL negotiation (authentication). */
  REXMPP_STREAM_SASL,
  /** Resource binding. */
  REXMPP_STREAM_BIND,
  /** Requesting stream management (XEP-0198) with resumption. */
  REXMPP_STREAM_SM_FULL,
  /** Requesting stream management just with acknowledgements. */
  REXMPP_STREAM_SM_ACKS,
  /** Resuming a stream. */
  REXMPP_STREAM_SM_RESUME,
  /** Restarting a stream. */
  REXMPP_STREAM_RESTART,
  /** The streams are ready for use: messaging and other higher-level
      things not covered here. */
  REXMPP_STREAM_READY,
  /** Stream closing is requested; at this state we're sending
      pending/queued messages and wrapping up stream management before
      actually closing it. */
  REXMPP_STREAM_CLOSE_REQUESTED,
  /** Closing a stream: sending the closing tag, waiting for a closing
      tag (and still accepting incoming messages). */
  REXMPP_STREAM_CLOSING,
  /** The server-to-client stream is closed. */
  REXMPP_STREAM_CLOSED,
  /** A stream error was detected in the server-to-client stream. */
  REXMPP_STREAM_ERROR
};

/** @brief TLS state */
enum tls_st {
  /** No active TLS connection. */
  REXMPP_TLS_INACTIVE,
  /** Awaiting direct TLS: this state may be set during a TCP
      connection establishment, so that we know if it's @c
      xmpps-client service. */
  REXMPP_TLS_AWAITING_DIRECT,
  /** Handshake is in progress. */
  REXMPP_TLS_HANDSHAKE,
  /** TLS connection is active. */
  REXMPP_TLS_ACTIVE,
  /** Closing a connection. */
  REXMPP_TLS_CLOSING,
  /** A connection is closed. */
  REXMPP_TLS_CLOSED,
  /** An error occurred. */
  REXMPP_TLS_ERROR
};

/** @brief SASL state */
enum sasl_st {
  REXMPP_SASL_INACTIVE,
  REXMPP_SASL_NEGOTIATION,
  REXMPP_SASL_ACTIVE,
  REXMPP_SASL_ERROR
};

/** @brief Stream management state */
enum sm_st {
  REXMPP_SM_INACTIVE,
  REXMPP_SM_NEGOTIATION,
  REXMPP_SM_ACTIVE
};

/** @brief Carbons state */
enum carbons_st {
  REXMPP_CARBONS_INACTIVE,
  REXMPP_CARBONS_NEGOTIATION,
  REXMPP_CARBONS_ACTIVE
};

/** Error codes. */
enum rexmpp_err {
  /** An operation is finished. */
  REXMPP_SUCCESS,
  /** An operation is in progress. */
  REXMPP_E_AGAIN,
  /** A message can't be queued for sending, because the queue is
      full. */
  REXMPP_E_SEND_QUEUE_FULL,
  /** The library can't take responsibility for message delivery (and
      doesn't try to send it), because XEP-0198 stanza queue is
      full. */
  REXMPP_E_STANZA_QUEUE_FULL,
  /** An operation (reading or sending) was cancelled by a user. */
  REXMPP_E_CANCELLED,
  /** An attempt to send while send buffer is empty. */
  REXMPP_E_SEND_BUFFER_EMPTY,
  /** An attempt to start sending while send buffer is not empty. */
  REXMPP_E_SEND_BUFFER_NOT_EMPTY,
  /** SASL-related error. */
  REXMPP_E_SASL,
  /** TLS-related error. */
  REXMPP_E_TLS,
  /** TCP-related error. */
  REXMPP_E_TCP,
  /** DNS-related error. */
  REXMPP_E_DNS,
  /** XML-related error. */
  REXMPP_E_XML,
  /** JID-related error. */
  REXMPP_E_JID,
  /** Failure to allocate memory. */
  REXMPP_E_MALLOC,
  /** Roster-related error. */
  REXMPP_E_ROSTER,
  /** A roster item is not found. */
  REXMPP_E_ROSTER_ITEM_NOT_FOUND,
  /** An erroneous parameter is supplied. */
  REXMPP_E_PARAM
};
typedef enum rexmpp_err rexmpp_err_t;

typedef void (*log_function_t) (rexmpp_t *s, int priority, const char *format, va_list args);
typedef int (*sasl_property_cb_t) (rexmpp_t *s, Gsasl_property prop);
typedef int (*xml_in_cb_t) (rexmpp_t *s, xmlNodePtr node);
typedef int (*xml_out_cb_t) (rexmpp_t *s, xmlNodePtr node);

/** @brief Complete connection state */
struct rexmpp
{
  /* Numeric states: governing future actions, helping to recall where
     we were at before returning from rexmpp_run, and communicating
     the overall current state to a user. */
  enum resolver_st resolver_state;
  enum tcp_st tcp_state;
  enum stream_st stream_state;
  enum tls_st tls_state;
  enum sasl_st sasl_state;
  enum sm_st sm_state;
  enum carbons_st carbons_state;

  /* Basic configuration. */
  const char *initial_jid;

  /* Manual host/port configuration. */
  const char *manual_host;
  uint16_t manual_port;
  int manual_direct_tls;

  /* Miscellaneous settings */
  const char *disco_node;

  /* Socks settings. */
  const char *socks_host;
  uint16_t socks_port;

  /* Various knobs (these are used instead of loadable modules). */
  int enable_carbons;
  int enable_service_discovery;
  int manage_roster;
  const char *roster_cache_file;

  /* Resource limits. */
  uint32_t stanza_queue_size;
  uint32_t send_queue_size;
  uint32_t iq_queue_size;

  /* Callbacks. */
  log_function_t log_function;
  sasl_property_cb_t sasl_property_cb;
  xml_in_cb_t xml_in_cb;
  xml_out_cb_t xml_out_cb;

  /* Stream-related state. */
  char *assigned_jid;
  xmlNodePtr stream_features;
  xmlNodePtr roster_items;
  char *roster_ver;

  /* Other dynamic data. */
  xmlNodePtr disco_info;

  /* IQs we're waiting for responses to. */
  rexmpp_iq_t *active_iq;

  /* Connection and stream management. */
  unsigned int id_counter;
  unsigned int reconnect_number;
  time_t reconnect_seconds;
  struct timeval next_reconnect_time;
  xmlNodePtr stanza_queue;
  uint32_t stanzas_out_count;
  uint32_t stanzas_out_acknowledged;
  uint32_t stanzas_in_count;
  char *stream_id;

  /* DNS-related structures. */
  ares_channel resolver_channel;
  struct ares_srv_reply *server_srv;
  struct ares_srv_reply *server_srv_cur;
  struct ares_srv_reply *server_srv_tls;
  struct ares_srv_reply *server_srv_tls_cur;

  /* The XMPP server we are connecting to. */
  const char *server_host;
  uint16_t server_port;

  /* The primary socket used for communication with the server. */
  int server_socket;

  /* A structure used to establish a TCP connection. */
  rexmpp_tcp_conn_t server_connection;
  /* A structure used to establish a SOCKS5 connection. */
  rexmpp_socks_t server_socks_conn;

  /* Send buffer. NULL if there is nothing to send (and must not be
     NULL if there is anything in the send queue). Not appending data
     to it, see send_queue for queuing. */
  char *send_buffer;
  ssize_t send_buffer_len;
  ssize_t send_buffer_sent;

  /* A queue of XML elements to send. */
  xmlNodePtr send_queue;

  /* XML parser context, and current element pointer for building
     XML nodes with a SAX2 parser interface. */
  xmlParserCtxtPtr xml_parser;
  xmlNodePtr current_element_root;
  xmlNodePtr current_element;

  /* TLS structures. */
  void *tls_session_data;
  size_t tls_session_data_size;
  gnutls_session_t gnutls_session;
  gnutls_certificate_credentials_t gnutls_cred;

  /* SASL structures. */
  Gsasl *sasl_ctx;
  Gsasl_session *sasl_session;
};

/**
   @brief ::rexmpp structure initialisation.
   @param[out] s An allocated structure.
   @param[in] jid Initial bare JID.
   @param[in] log_function A user-provided logging function, can be
   NULL.
   @param[in] sasl_property_cb A callback to ask for SASL properties
   (such as password).
   @param[in] xml_in_cb A function to handle incoming XML elements. It
   is called before other processing, so it can alter the elements, or
   interrupt processing by returning a non-zero value. Optional.
   @param[in] xml_out_cb Akin to the previous one, but for outbound
   elements.
   @returns ::REXMPP_SUCCESS or some ::rexmpp_err error.
 */
rexmpp_err_t rexmpp_init (rexmpp_t *s,
                          const char *jid,
                          log_function_t log_function,
                          sasl_property_cb_t sasl_property_cb,
                          xml_in_cb_t xml_in_cb,
                          xml_out_cb_t xml_out_cb);
/**
   @brief ::rexmpp structure deinitialisation. This will free all the
   allocated resources.
   @param[in,out] s A structure to deinitialise.
*/
void rexmpp_done (rexmpp_t *s);

/**
   @brief Runs a single iteration.
   @param[in,out] s An initialised :rexmpp structure.
   @param[in] File descriptors available for reading from.
   @param[in] write_fds File descriptors available for writing to.

   \callergraph
*/
rexmpp_err_t rexmpp_run (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds);

/**
   @brief Requests stream closing.
*/
rexmpp_err_t rexmpp_stop (rexmpp_t *s);

/**
   @brief Sends (or queues, or at least tries to, if everything goes
   well) an XML element.
   @param[in,out] s A ::rexmpp structure.
   @param[in] node An XML element to send. The library assumes
   ownership of the element, so it must not be freed by the caller.
*/
rexmpp_err_t rexmpp_send (rexmpp_t *s, xmlNodePtr node);

/**
   @brief Prepare and send a new info/query request.
   @param[in,out] s ::rexmpp
   @param[in] type
   @param[in] to
   @param[in] payload IQ payload, the library assumes ownership of it.
   @param[in] cb A ::rexmpp_iq_callback_t function to call on reply
   (or if we will give up on it), can be NULL.

   This function is specifically for IQs that should be tracked by the
   library. If an application wants to track replies on its own, it
   should use ::rexmpp_send.
*/
void rexmpp_iq_new (rexmpp_t *s,
                    const char *type,
                    const char *to,
                    xmlNodePtr payload,
                    rexmpp_iq_callback_t cb);

struct timeval *rexmpp_timeout (rexmpp_t *s, struct timeval *max_tv, struct timeval *tv);
int rexmpp_fds (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds);


char *rexmpp_xml_serialize (xmlNodePtr node);
xmlNodePtr rexmpp_xml_add_id (rexmpp_t *s, xmlNodePtr node);

void rexmpp_log (rexmpp_t *s, int priority, const char *format, ...);
int rexmpp_xml_match (xmlNodePtr node,
                      const char *namespace,
                      const char *name);
#endif
