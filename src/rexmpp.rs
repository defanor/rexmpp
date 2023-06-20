extern crate libc;
use std::os::raw::{c_char, c_int, c_void, c_uint};
use libc::{time_t, timespec};

use super::{rexmpp_jid, rexmpp_xml, rexmpp_dns, rexmpp_tcp, rexmpp_socks};

#[derive(PartialEq)]
#[repr(C)]
pub enum ResolverState {
    Ready,
    SRV,
    SRV2,
    Failure
}

#[derive(PartialEq)]
#[repr(C)]
pub enum TCPState {
    None,
    Connecting,
    SOCKS,
    Connected,
    Closed,
    ConnectionFailure,
    Error
}

#[derive(PartialEq)]
#[repr(C)]
pub enum StreamState {
    None,
    Opening,
    StartTLS,
    SASL,
    Bind,
    SMFull,
    SMAcks,
    SMResume,
    Ready,
    CloseRequested,
    Closing,
    Closed,
    Error,
    ErrorReconnect
}

#[derive(PartialEq)]
#[repr(C)]
pub enum TLSState {
    Inactive,
    AwaitingDirect,
    Handshake,
    Active,
    Closing,
    Closed,
    Error
}

#[derive(PartialEq)]
#[repr(C)]
pub enum SASLState {
    Inactive,
    Negotiation,
    Active,
    Error
}

#[derive(PartialEq)]
#[repr(C)]
pub enum SMState {
    Inactive,
    Negotiation,
    Active
}

#[derive(PartialEq)]
#[repr(C)]
pub enum CarbonsState {
    Inactive,
    Negotiation,
    Active
}

#[derive(PartialEq)]
#[repr(C)]
pub enum TLSPolicy {
    Require,
    Prefer,
    Avoid
}

type IQCallback = unsafe extern "C"
fn (s: *mut Rexmpp, cb_data: *mut c_void,
    request: *mut rexmpp_xml::RexmppXML, response: *mut rexmpp_xml::RexmppXML,
    success: c_int) -> ();

#[repr(C)]
pub struct RexmppIQ {
    pub requset: *mut rexmpp_xml::RexmppXML,
    pub cb: IQCallback,
    pub cb_data: *const c_void,
    pub next: *mut RexmppIQ
}

#[repr(C)]
pub struct Rexmpp {
    pub resolver_state: ResolverState,
    pub tcp_state: TCPState,
    pub stream_state: StreamState,
    pub tls_state: TLSState,
    pub sasl_state: SASLState,
    pub sm_state: SMState,
    pub carbons_state: CarbonsState,

    // Basic configuration
    pub initial_jid: rexmpp_jid::RexmppJID,

    // Manual host/port configuration
    pub manual_host: *const c_char,
    pub manual_port: u16,
    pub manual_direct_tls: c_int,

    // Miscellaneous settings
    pub disco_node: *const c_char,

    // SOCKS settings
    pub socks_host: *const c_char,
    pub socks_port: u16,

    // Various knobs (these are used instead of loadable modules)
    pub enable_carbons: c_int,           // XEP-0280
    pub manage_roster: c_int,
    pub roster_cache_file: *const c_char,
    pub track_roster_presence: c_int,
    pub track_roster_events: c_int,      // XEP-0163
    pub nick_notifications: c_int,       // XEP-0172
    pub retrieve_openpgp_keys: c_int,    // XEP-0373
    pub autojoin_bookmarked_mucs: c_int, // XEP-0402
    pub tls_policy: TLSPolicy,
    pub enable_jingle: c_int,
    pub client_name: *const c_char,      // XEP-0030, XEP-0092
    pub client_type: *const c_char,      // XEP-0030
    pub client_version: *const c_char,   // XEP-0092
    pub local_address: *const c_char,    // For ICE, XEP-0176
    pub jingle_prefer_rtcp_mux: c_int,
    // An IP_MTU_DISCOVER parameter for TCP sockets, or -1 to not set
    // it
    pub path_mtu_discovery: c_int,
    // Resource limits
    pub stanza_queue_size: u32,
    pub send_queue_size: u32,
    pub iq_queue_size: u32,
    pub iq_cache_size: u32,
    pub max_jingle_sessions: u32,

    // Callbacks

    // c_variadic is experimental and cannot be used on the stable
    // release channel, so skipping the log function callback.
    pub log_function: *const c_void,
    // Actually skipping proper definitions of others for now as well
    // (TODO: add them).
    pub sasl_property_cb: *const c_void,
    pub xml_in_cb: *const c_void,
    pub xml_out_cb: *const c_void,
    pub roster_modify_cb: *const c_void,
    pub console_print_cb: *const c_void,

    // Stream-related state
    pub assigned_jid: rexmpp_jid::RexmppJID,
    pub stream_features: *mut rexmpp_xml::RexmppXML,
    pub roster_items: *mut rexmpp_xml::RexmppXML,
    pub roster_ver: *mut c_char,
    pub roster_presence: *mut rexmpp_xml::RexmppXML,
    pub roster_events: *mut rexmpp_xml::RexmppXML,

    // Other dynamic data
    pub disco_info: *mut rexmpp_xml::RexmppXML,
    // Includes Jingle RTP session candidates; rexmpp prioritizes the
    // ones listed earlier on incoming calls
    pub jingle_rtp_description: *mut rexmpp_xml::RexmppXML,

    // IQs we're waiting for responses to
    pub active_iq: *mut RexmppIQ,
    pub iq_cache: *mut rexmpp_xml::RexmppXML,

    // Jingle context
    pub jingle: *const c_void,      // TODO

    // Connection and stream management
    pub reconnect_number: c_uint,
    pub reconnect_seconds: time_t,
    pub next_reconnect_time: timespec,
    pub stanza_queue: *mut rexmpp_xml::RexmppXML,
    pub stanzas_out_count: u32,
    pub stanzas_out_acknowledged: u32,
    pub stanzas_in_count: u32,
    pub stream_id: *mut c_char,

    // Server ping configuration and state
    pub ping_delay: c_int,
    pub ping_requested: c_int,
    pub last_network_activity: time_t,

    // DNS-related structures
    pub resolver: *mut c_void,
    pub server_srv: *mut rexmpp_dns::RexmppDNSResult,
    pub server_srv_cur: c_int,
    pub server_srv_tls: *mut rexmpp_dns::RexmppDNSResult,
    pub server_srv_tls_cur: c_int,
    pub server_active_srv: *mut rexmpp_dns::RexmppDNSSRV,

    // The XMPP server we are connecting to
    pub server_host: *const c_char,
    pub server_port: u16,

    // The primary socket used for communication with the server
    pub server_socket: c_int,
    // Whether the address it's connected to was verified with DNSSEC
    pub server_socket_dns_secure: c_int,

    // A structure used to establish a TCP connection
    pub server_connection: rexmpp_tcp::RexmppTCPConnection,
    pub server_socks_conn: rexmpp_socks::RexmppSocks,

    // Send buffer. NULL if there is nothing to send (and must not be
    // NULL if there is anything in the send queue). Not appending
    // data to it, see send_queue for queuing.
    pub send_buffer: *mut c_char,
    pub send_buffer_len: isize,
    pub send_buffer_sent: isize,

    // A queue of XML elements to send
    pub send_queue: *mut rexmpp_xml::RexmppXML,

    // XML parser context, and current element pointer for building
    // XML nodes with a SAX2 parser interface
    pub xml_parser: *mut c_void,
    pub current_element_root: *mut c_void,
    pub current_element: *mut c_void,
    pub input_queue: *mut c_void,
    pub input_queue_last: *mut c_void,

    // TLS structures
    pub tls: *mut c_void,

    // SASL structures
    pub sasl: *mut c_void,

    // OpenPGP structures
    pub pgp_ctx: *mut c_void,

    // curl structures
    pub curl_multi: *mut c_void
}
