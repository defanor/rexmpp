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
#include <unbound.h>
#include <gnutls/gnutls.h>
#include <gsasl.h>
#include <libxml/tree.h>
#include <gpgme.h>
#include "rexmpp_tcp.h"
#include "rexmpp_socks.h"
#include "rexmpp_dns.h"
#include "rexmpp_jid.h"

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
typedef enum rexmpp_err rexmpp_err_t;

typedef void (*log_function_t) (rexmpp_t *s, int priority, const char *format, va_list args);
typedef int (*sasl_property_cb_t) (rexmpp_t *s, Gsasl_property prop);
typedef int (*xml_in_cb_t) (rexmpp_t *s, xmlNodePtr node);
typedef int (*xml_out_cb_t) (rexmpp_t *s, xmlNodePtr node);
typedef void (*roster_modify_cb_t) (rexmpp_t *s, xmlNodePtr item);
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
  int enable_service_discovery; /* XEP-0030 */
  int manage_roster;
  const char *roster_cache_file;
  int track_roster_presence;
  int track_roster_events;      /* XEP-0163 */
  int nick_notifications;       /* XEP-0172 */
  int retrieve_openpgp_keys;    /* XEP-0373 */
  int autojoin_bookmarked_mucs; /* XEP-0402 */

  /* Resource limits. */
  uint32_t stanza_queue_size;
  uint32_t send_queue_size;
  uint32_t iq_queue_size;

  /* Callbacks. */
  log_function_t log_function;
  sasl_property_cb_t sasl_property_cb;
  xml_in_cb_t xml_in_cb;
  xml_out_cb_t xml_out_cb;
  roster_modify_cb_t roster_modify_cb;
  console_print_cb_t console_print_cb;

  /* Stream-related state. */
  struct rexmpp_jid assigned_jid;
  xmlNodePtr stream_features;
  xmlNodePtr roster_items;
  char *roster_ver;
  xmlNodePtr roster_presence;
  xmlNodePtr roster_events;

  /* Other dynamic data. */
  xmlNodePtr disco_info;

  /* IQs we're waiting for responses to. */
  rexmpp_iq_t *active_iq;

  /* Connection and stream management. */
  unsigned int reconnect_number;
  time_t reconnect_seconds;
  struct timeval next_reconnect_time;
  xmlNodePtr stanza_queue;
  uint32_t stanzas_out_count;
  uint32_t stanzas_out_acknowledged;
  uint32_t stanzas_in_count;
  char *stream_id;

  /* Server ping configuration and state. */
  int ping_delay;
  int ping_requested;
  time_t last_network_activity;

  /* DNS-related structures. */
  struct ub_ctx *resolver_ctx;
  struct ub_result *server_srv;
  int server_srv_cur;
  struct ub_result *server_srv_tls;
  int server_srv_tls_cur;
  struct rexmpp_dns_srv server_active_srv;

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
  ssize_t send_buffer_len;
  ssize_t send_buffer_sent;

  /* A queue of XML elements to send. */
  xmlNodePtr send_queue;

  /* XML parser context, and current element pointer for building
     XML nodes with a SAX2 parser interface. */
  xmlParserCtxtPtr xml_parser;
  xmlNodePtr current_element_root;
  xmlNodePtr current_element;
  xmlNodePtr input_queue;
  xmlNodePtr input_queue_last;

  /* TLS structures. */
  void *tls_session_data;
  size_t tls_session_data_size;
  gnutls_session_t gnutls_session;
  gnutls_certificate_credentials_t gnutls_cred;

  /* SASL structures. */
  Gsasl *sasl_ctx;
  Gsasl_session *sasl_session;

  /* OpenPGP structures */
  gpgme_ctx_t pgp_ctx;
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
rexmpp_err_t rexmpp_iq_new (rexmpp_t *s,
                            const char *type,
                            const char *to,
                            xmlNodePtr payload,
                            rexmpp_iq_callback_t cb);

/**
   @brief Determines the maximum time to wait before the next
   ::rexmpp_run call.
   @param[in] s ::rexmpp
   @param[in] max_tv An existing timeout (can be NULL), to return if
   there's no more urgent timeouts.
   @param[in,out] tv An allocated timeval structure, to store the time
   in.
   @returns A pointer to either max_tv or tv.
*/
struct timeval *rexmpp_timeout (rexmpp_t *s,
                                struct timeval *max_tv,
                                struct timeval *tv);

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
   @brief A helper function for XML parsing.
   @param[in] str A string to parse.
   @param[in] str_len String length.
   @returns Parsed XML, or NULL on failure.
*/
xmlNodePtr rexmpp_xml_parse (const char *str, int str_len);

/**
   @brief A helper function for XML serialisation.
   @param[in] node An XML node.
   @returns A string (must be freed by the caller).
*/
char *rexmpp_xml_serialize (xmlNodePtr node);

/**
   @brief Adds an "id" attribute to an XML stanza.
   @param[in,out] s ::rexmpp
   @param[in] node A pointer to an XML stanza.
   @returns The same pointer as on input, for more convenient
   composition.
*/
xmlNodePtr rexmpp_xml_add_id (rexmpp_t *s, xmlNodePtr node);

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

/**
   @brief Matches an XML node against a namespace and an element name.
   @param[in] node An XML node to match.
   @param[in] namespace An XML namespace. Can be NULL (matches
   anything), and it is assumed that the default namespace is
   "jabber:client" (so if it is "jabber:client" and an element doesn't
   have a namespace defined, this function counts that as a match).
   @param[in] name Element name. Can be NULL (matches anything).
   @returns 1 on a successful match, 0 otherwise.
*/
int rexmpp_xml_match (xmlNodePtr node,
                      const char *namespace,
                      const char *name);

/**
   @brief Finds a child element of an XML node, which matches the
   given namespace and name.
   @param[in] node The node containing child nodes.
   @param[in] namespace The namespace to look for.
   @param[in] name The element name to look for.
   @returns A pointer to the first matching child node, or NULL if no
   matching child elements found.
*/
xmlNodePtr rexmpp_xml_find_child (xmlNodePtr node,
                                  const char *namespace,
                                  const char *name);

/**
   @brief Finds a PEP event.
   @param[in] s ::rexmpp
   @param[in] from JID.
   @param[in] node PEP node.
   @param[out] prev_event The event preceding the returned one.
   @returns A pointer to the message announcing an event, or NULL on
   failure.
*/
xmlNodePtr rexmpp_find_event (rexmpp_t *s,
                              const char *from,
                              const char *node,
                              xmlNodePtr *prev_event);

void rexmpp_console_feed (rexmpp_t *s, char *str, ssize_t str_len);

/**
   @brief A strerror function for ::rexmpp_err
   @param[in] error Error code, as returned by rexmpp functions.
   @returns A string explaining the error.
*/
const char *rexmpp_strerror (rexmpp_err_t error);

#endif
