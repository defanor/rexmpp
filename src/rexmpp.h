/**
   @file rexmpp.h
   @brief rexmpp, a reusable XMPP IM client library.
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#ifndef REXMPP_H
#define REXMPP_H

#include <stdint.h>

#include "config.h"

#ifdef HAVE_GPGME
#include <gpgme.h>
#endif
#ifdef HAVE_CURL
#include <curl/curl.h>
#endif

typedef struct rexmpp rexmpp_t;

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
  /** OpenPGP-related error. */
  REXMPP_E_PGP,
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
  REXMPP_E_PARAM,
  /** A stream error. */
  REXMPP_E_STREAM,
  /** An unspecified error. */
  REXMPP_E_OTHER
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
  REXMPP_STREAM_ERROR,
  /** A stream error that should be fixed by a reconnect. */
  REXMPP_STREAM_ERROR_RECONNECT
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

/** @brief TLS policy */
enum tls_pol {
  REXMPP_TLS_REQUIRE,
  REXMPP_TLS_PREFER,
  REXMPP_TLS_AVOID
};

typedef enum rexmpp_err rexmpp_err_t;

#include "rexmpp_xml.h"
#include "rexmpp_xml_parser.h"
#include "rexmpp_tcp.h"
#include "rexmpp_socks.h"
#include "rexmpp_dns.h"
#include "rexmpp_tls.h"
#include "rexmpp_jid.h"
#include "rexmpp_jingle.h"
#include "rexmpp_sasl.h"

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
                                      void *cb_data,
                                      rexmpp_xml_t *request,
                                      rexmpp_xml_t *response,
                                      int success);

typedef struct rexmpp_iq rexmpp_iq_t;

/** @brief A pending info/query request. */
struct rexmpp_iq
{
  /** @brief The sent request. */
  rexmpp_xml_t *request;
  /** @brief A callback to call on reply. */
  rexmpp_iq_callback_t cb;
  /** @brief User-supplied data, to pass to a callback function. */
  void *cb_data;
  /** @brief Next pending IQ. */
  rexmpp_iq_t *next;
};

typedef void (*log_function_t) (rexmpp_t *s, int priority, const char *format, va_list args);
typedef int (*sasl_property_cb_t) (rexmpp_t *s, rexmpp_sasl_property prop);
typedef int (*xml_in_cb_t) (rexmpp_t *s, rexmpp_xml_t *node);
typedef int (*xml_out_cb_t) (rexmpp_t *s, rexmpp_xml_t *node);
typedef void (*roster_modify_cb_t) (rexmpp_t *s, rexmpp_xml_t *item);
typedef int (*console_print_cb_t) (rexmpp_t *s, const char *format, va_list args);

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
  struct rexmpp_jid initial_jid;

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
  int enable_carbons;           /* XEP-0280 */
  int manage_roster;
  const char *roster_cache_file;
  int track_roster_presence;
  int track_roster_events;      /* XEP-0163 */
  int nick_notifications;       /* XEP-0172 */
  int retrieve_openpgp_keys;    /* XEP-0373 */
  int autojoin_bookmarked_mucs; /* XEP-0402 */
  enum tls_pol tls_policy;
  int enable_jingle;
  const char *client_name;      /* XEP-0030, XEP-0092 */
  const char *client_type;      /* XEP-0030 */
  const char *client_version;   /* XEP-0092 */
  const char *local_address;    /* For ICE, XEP-0176 */
  int jingle_prefer_rtcp_mux;
  int path_mtu_discovery;       /* An IP_MTU_DISCOVER parameter for
                                   TCP sockets, or -1 to not set it */

  /* Resource limits. */
  uint32_t stanza_queue_size;
  uint32_t send_queue_size;
  uint32_t iq_queue_size;
  uint32_t iq_cache_size;
  uint32_t max_jingle_sessions;

  /* Callbacks. */
  log_function_t log_function;
  sasl_property_cb_t sasl_property_cb;
  xml_in_cb_t xml_in_cb;
  xml_out_cb_t xml_out_cb;
  roster_modify_cb_t roster_modify_cb;
  console_print_cb_t console_print_cb;

  /* Stream-related state. */
  struct rexmpp_jid assigned_jid;
  rexmpp_xml_t *stream_features;
  rexmpp_xml_t *roster_items;
  char *roster_ver;
  rexmpp_xml_t *roster_presence;
  rexmpp_xml_t *roster_events;

  /* Other dynamic data. */
  rexmpp_xml_t *disco_info;
  /* Includes Jingle RTP session candidates; rexmpp prioritizes the
     ones listed earlier on incoming calls. */
  rexmpp_xml_t *jingle_rtp_description;

  /* IQs we're waiting for responses to. */
  rexmpp_iq_t *active_iq;

  /* Cached IQ requests and responses. */
  rexmpp_xml_t *iq_cache;

  /* Jingle context. */
  rexmpp_jingle_ctx_t *jingle;

  /* Connection and stream management. */
  unsigned int reconnect_number;
  time_t reconnect_seconds;
  struct timespec next_reconnect_time;
  rexmpp_xml_t *stanza_queue;
  uint32_t stanzas_out_count;
  uint32_t stanzas_out_acknowledged;
  uint32_t stanzas_in_count;
  char *stream_id;

  /* Server ping configuration and state. */
  int ping_delay;
  int ping_requested;
  struct timespec last_network_activity;

  /* DNS-related structures. */
  rexmpp_dns_ctx_t resolver;
  rexmpp_dns_result_t *server_srv;
  int server_srv_cur;
  rexmpp_dns_result_t *server_srv_tls;
  int server_srv_tls_cur;
  struct rexmpp_dns_srv *server_active_srv;

  /* The XMPP server we are connecting to. */
  const char *server_host;
  uint16_t server_port;

  /* The primary socket used for communication with the server. */
  int server_socket;
  /* Whether the address it's connected to was verified with
     DNSSEC. */
  int server_socket_dns_secure;

  /* A structure used to establish a TCP connection. */
  rexmpp_tcp_conn_t server_connection;
  /* A structure used to establish a SOCKS5 connection. */
  rexmpp_socks_t server_socks_conn;

  /* Send buffer. NULL if there is nothing to send (and must not be
     NULL if there is anything in the send queue). Not appending data
     to it, see send_queue for queuing. */
  char *send_buffer;
  size_t send_buffer_len;
  size_t send_buffer_sent;

  /* A queue of XML elements to send. */
  rexmpp_xml_t *send_queue;

  /* An input queue of parsed XML structures. */
  rexmpp_xml_t *input_queue;
  rexmpp_xml_t *input_queue_last;

  /* XML parser context, and current element pointer for building
     XML nodes with a SAX2 parser interface. */
  rexmpp_xml_parser_ctx_t xml_parser;

  /* The children are stored in reverse order during building. */
  rexmpp_xml_t *current_element_root;
  rexmpp_xml_t *current_element;

  /* TLS structures. */
  rexmpp_tls_t *tls;

  /* SASL structures. */
  rexmpp_sasl_ctx_t *sasl;

  /* OpenPGP structures */
#ifdef HAVE_GPGME
  gpgme_ctx_t pgp_ctx;
#else
  void *pgp_ctx;
#endif

  /* curl structures */
#ifdef HAVE_CURL
  CURLM *curl_multi;
#else
  void *curl_multi;
#endif
};

/**
   @brief ::rexmpp structure initialisation.
   @param[out] s An allocated structure.
   @param[in] jid Initial bare JID.
   @returns ::REXMPP_SUCCESS or some ::rexmpp_err error.
 */
rexmpp_err_t rexmpp_init (rexmpp_t *s,
                          const char *jid,
                          log_function_t log_function);

/**
   @brief ::rexmpp structure deinitialisation. This will free all the
   allocated resources.
   @param[in,out] s A structure to deinitialise.
*/
void rexmpp_done (rexmpp_t *s);

/**
   @brief Runs a single iteration.
   @param[in,out] s An initialised ::rexmpp structure.
   @param[in] read_fds File descriptors available for reading from.
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
rexmpp_err_t rexmpp_send (rexmpp_t *s, rexmpp_xml_t *node);

/**
   @brief Prepare and send a new info/query request.
   @param[in,out] s ::rexmpp
   @param[in] type
   @param[in] to
   @param[in] payload IQ payload, the library assumes ownership of it.
   @param[in] cb A ::rexmpp_iq_callback_t function to call on reply
   (or if we will give up on it), can be NULL.
   @param[in] cb_data A data pointer to pass to cb.

   This function is specifically for IQs that should be tracked by the
   library. If an application wants to track replies on its own, it
   should use ::rexmpp_send.
*/
rexmpp_err_t rexmpp_iq_new (rexmpp_t *s,
                            const char *type,
                            const char *to,
                            rexmpp_xml_t *payload,
                            rexmpp_iq_callback_t cb,
                            void *cb_data);

/**
   @brief Same as ::rexmpp_iq_new, but caches responses, and can use
   cached ones.
   @param[in] fresh Do not read cache, make a new request.
*/
rexmpp_err_t rexmpp_cached_iq_new (rexmpp_t *s,
                                   const char *type,
                                   const char *to,
                                   rexmpp_xml_t *payload,
                                   rexmpp_iq_callback_t cb,
                                   void *cb_data,
                                   int fresh);

/**
   @brief Reply to an IQ.
*/
void rexmpp_iq_reply (rexmpp_t *s,
                      rexmpp_xml_t *req,
                      const char *type,
                      rexmpp_xml_t *payload);

/**
   @brief Determines the maximum time to wait before the next
   ::rexmpp_run call.
   @param[in] s ::rexmpp
   @param[in] max_tv An existing timeout (can be NULL), to return if
   there's no more urgent timeouts.
   @param[in,out] tv An allocated timespec structure, to store the
   time in.
   @returns A pointer to either max_tv or tv.
*/
struct timespec *rexmpp_timeout (rexmpp_t *s,
                                 struct timespec *max_tv,
                                 struct timespec *tv);

/**
   @brief Sets file descriptors to watch.
   @param[in] s ::rexmpp
   @param[out] read_fds File descriptor set to monitor for read
   events.
   @param[out] write_fds File descriptor set to monitor for write
   events.
   @returns The highest-numbered file descriptor, plus 1. Suitable for
   select(2) calls.
*/
int rexmpp_fds (rexmpp_t *s, fd_set *read_fds, fd_set *write_fds);

/**
   @brief The logging function.
   @param[in] s ::rexmpp
   @param[in] priority A syslog priority.
   @param[in] format
*/

void rexmpp_log (rexmpp_t *s, int priority, const char *format, ...);

/**
   @brief Gets an appropriate display name for a JID.
   @param[in] s ::rexmpp
   @param[in] jid_str A JID string.
   @returns A newly allocated null-terminated string, or NULL on
   error.
*/
char *rexmpp_get_name (rexmpp_t *s, const char *jid_str);

char *rexmpp_gen_id (rexmpp_t *s);

/**
   @brief Finds a PEP event.
   @param[in] s ::rexmpp
   @param[in] from JID.
   @param[in] node PEP node.
   @param[out] prev_event The event preceding the returned one.
   @returns A pointer to the message announcing an event, or NULL on
   failure.
*/
rexmpp_xml_t *rexmpp_find_event (rexmpp_t *s,
                                      const char *from,
                                      const char *node,
                                      rexmpp_xml_t **prev_event);

void rexmpp_console_feed (rexmpp_t *s, char *str, ssize_t str_len);

/**
   @brief A strerror function for ::rexmpp_err
   @param[in] error Error code, as returned by rexmpp functions.
   @returns A string explaining the error.
*/
const char *rexmpp_strerror (rexmpp_err_t error);


/**
   @brief Recurisevly searches for a given feature, using service
   discovery, starting from a given JID. If it finds such a feature,
   it call the provided callback, providing it both IQ request and
   response for the entity that provided the feature; if the feature
   isn't found, it calls the callback with NULL values.

   @param[in,out] s ::rexmpp
   @param[in] jid An XMPP address to start searching from.
   @param[in] feature_var A feature to search for.
   @param[in] cb A ::rexmpp_iq_callback_t function to call on reply.
   @param[in] cb_data A data pointer to pass to cb.
   @param[in] fresh Force a new request, instead of looking up the
   cache.
   @param[in] max_requests Maximum number of IQ requests to perform
   before giving up.
*/
rexmpp_err_t
rexmpp_disco_find_feature (rexmpp_t *s,
                           const char *jid,
                           const char *feature_var,
                           rexmpp_iq_callback_t cb,
                           void *cb_data,
                           int fresh,
                           int max_requests);

#endif
