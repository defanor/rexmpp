use std::os::raw::{c_int, c_char};
use libc::*;
use std::ptr::{null_mut,null};
use std::mem;
use errno::{errno};

use super::{rexmpp_dns, rexmpp};


#[link(name = "libc")]
extern {
    fn inet_pton (af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
}


const REXMPP_TCP_MAX_CONNECTION_ATTEMPTS: usize = 20;
const REXMPP_TCP_IPV6_DELAY_MS: i64 = 50;
const REXMPP_TCP_CONN_DELAY_MS: i64 = 250;

#[derive(PartialEq, Copy, Clone)]
#[repr(C)]
pub enum ResolutionStatus {
    Inactive,
    Waiting,
    Success,
    Failure
}

#[derive(PartialEq, Copy, Clone)]
#[repr(C)]
pub enum ConnectionError {
    Done,
    ResolverError,
    InProgress,
    Failure,
    Error
}

#[repr(C)]
pub struct RexmppTCPConnection {
    pub host: *const c_char,
    pub port: u16,
    pub resolution_v4: ResolutionStatus,
    pub resolver_status_v4: c_int,
    pub resolved_v4: *mut rexmpp_dns::RexmppDNSResult,
    pub addr_cur_v4: c_int,
    pub resolution_v6: ResolutionStatus,
    pub resolver_status_v6: c_int,
    pub resolved_v6: *mut rexmpp_dns::RexmppDNSResult,
    pub addr_cur_v6: c_int,
    pub sockets: [c_int; REXMPP_TCP_MAX_CONNECTION_ATTEMPTS],
    pub connection_attempts: c_int,
    pub next_connection_time: timespec,
    pub fd: c_int,
    pub dns_secure: bool
}

#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_dns_aaaa_cb (_s: *mut rexmpp::Rexmpp,
                           ptr: *mut c_void,
                           result: *mut rexmpp_dns::RexmppDNSResult)
                           -> () {
    let conn = ptr as *mut RexmppTCPConnection;
    (*conn).resolved_v6 = result;
    if result != null_mut() {
        (*conn).resolution_v6 = ResolutionStatus::Success;
        (*conn).addr_cur_v6 = -1;
    } else {
        (*conn).resolution_v6 = ResolutionStatus::Failure;
    }
}

#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_dns_a_cb (_s: *mut rexmpp::Rexmpp,
                        ptr: *mut c_void,
                        result: *mut rexmpp_dns::RexmppDNSResult)
                        -> () {
    let conn = ptr as *mut RexmppTCPConnection;
    (*conn).resolved_v4 = result;
    if result != null_mut() {
        (*conn).resolution_v4 = ResolutionStatus::Success;
        (*conn).addr_cur_v4 = -1;
        if (*conn).resolution_v6 == ResolutionStatus::Waiting {
            // Wait a bit (usually 50 ms) for IPv6
            clock_gettime(CLOCK_MONOTONIC, &mut (*conn).next_connection_time);
            (*conn).next_connection_time.tv_nsec += REXMPP_TCP_IPV6_DELAY_MS * 1000000;
            if (*conn).next_connection_time.tv_nsec >= 1000000000 {
                (*conn).next_connection_time.tv_nsec -= 1000000000;
                (*conn).next_connection_time.tv_sec += 1;
            }
        }
    } else {
        (*conn).resolution_v4 = ResolutionStatus::Failure;
    }
}


#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_cleanup (conn: *mut RexmppTCPConnection) -> () {
    for i in 0..=(REXMPP_TCP_MAX_CONNECTION_ATTEMPTS - 1) {
        if (*conn).sockets[i] != -1 && (*conn).sockets[i] != (*conn).fd {
            close((*conn).sockets[i]);
            (*conn).sockets[i] = -1;
        }
    }
    if (*conn).resolution_v4 != ResolutionStatus::Inactive {
        (*conn).resolution_v4 = ResolutionStatus::Inactive;
        (*conn).resolution_v6 = ResolutionStatus::Inactive;
    }
    if (*conn).resolved_v4 != null_mut() {
        rexmpp_dns::rexmpp_dns_result_free((*conn).resolved_v4);
        (*conn).resolved_v4 = null_mut();
    }
    if (*conn).resolved_v6 != null_mut() {
        rexmpp_dns::rexmpp_dns_result_free((*conn).resolved_v6);
        (*conn).resolved_v6 = null_mut();
    }
}

#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_connected (conn: *mut RexmppTCPConnection, fd: c_int)
                         -> ConnectionError {
    let mut sa_ptr = mem::MaybeUninit::<sockaddr>::uninit();
    let mut sa_len : socklen_t = mem::size_of::<sockaddr>() as u32;
    getsockname(fd, sa_ptr.as_mut_ptr(), &mut sa_len);
    let sa = sa_ptr.assume_init();
    if sa.sa_family == (AF_INET as u16)
        && (*conn).resolved_v4 != null_mut() {
            (*conn).dns_secure = (*(*conn).resolved_v4).secure;
        }
    else if sa.sa_family == (AF_INET6 as u16)
        && (*conn).resolved_v6 != null_mut() {
            (*conn).dns_secure = (*(*conn).resolved_v6).secure;
        }
    (*conn).fd = fd;
    rexmpp_tcp_cleanup(conn);
    return ConnectionError::Done;
}

#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_socket (s: *mut rexmpp::Rexmpp, domain: c_int) -> c_int {
    let sock: c_int = socket(domain, SOCK_STREAM, 0);

    // Make it non-blocking
    let flags: c_int = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Call the socket creation callback, if provided
    ((*s).socket_cb).map(|cb| cb(s, sock));

    return sock;
}

#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_conn_init (s: *mut rexmpp::Rexmpp,
                         conn: *mut RexmppTCPConnection,
                         host: *const c_char,
                         port: u16)
                         -> ConnectionError {
    for i in 0..=(REXMPP_TCP_MAX_CONNECTION_ATTEMPTS - 1) {
        (*conn).sockets[i] = -1;
    }
    (*conn).connection_attempts = 0;
    (*conn).port = port;
    (*conn).resolved_v4 = null_mut();
    (*conn).resolved_v6 = null_mut();
    (*conn).fd = -1;
    (*conn).dns_secure = false;
    (*conn).next_connection_time.tv_sec = 0;
    (*conn).next_connection_time.tv_nsec = 0;

    (*conn).resolution_v4 = ResolutionStatus::Inactive;
    (*conn).resolution_v6 = ResolutionStatus::Inactive;

    let mut addr_v4 = mem::MaybeUninit::<sockaddr_in>::uninit();
    if inet_pton(AF_INET, host,
                 &mut ((*addr_v4.as_mut_ptr()).sin_addr)
                 as *mut in_addr as *mut c_void) == 1 {
        (*addr_v4.as_mut_ptr()).sin_family = AF_INET as u16;
        (*addr_v4.as_mut_ptr()).sin_port = port.to_be();
        (*conn).sockets[(*conn).connection_attempts as usize] =
            rexmpp_tcp_socket(s, AF_INET);
        if connect((*conn).sockets[(*conn).connection_attempts as usize],
                   addr_v4.as_mut_ptr() as *mut sockaddr,
                   mem::size_of::<sockaddr_in>() as u32) != 0 {
            if errno().0 != EINPROGRESS {
                return ConnectionError::Error;
            }
        } else {
            return rexmpp_tcp_connected(conn,
                                        (*conn).sockets[(*conn).connection_attempts as usize]);
        }
        (*conn).connection_attempts += 1;
        return ConnectionError::InProgress;
    }

    let mut addr_v6 = mem::MaybeUninit::<sockaddr_in6>::uninit();
    if inet_pton(AF_INET6, host,
                 &mut ((*addr_v6.as_mut_ptr()).sin6_addr)
                 as *mut in6_addr as *mut c_void) == 1 {
        (*addr_v6.as_mut_ptr()).sin6_family = AF_INET as u16;
        (*addr_v6.as_mut_ptr()).sin6_port = port.to_be();
        (*addr_v6.as_mut_ptr()).sin6_flowinfo = 0;
        (*addr_v6.as_mut_ptr()).sin6_scope_id = 0;
        (*conn).sockets[(*conn).connection_attempts as usize] =
            rexmpp_tcp_socket(s, AF_INET6);
        if connect((*conn).sockets[(*conn).connection_attempts as usize],
                   addr_v6.as_mut_ptr() as *mut sockaddr,
                   mem::size_of::<sockaddr_in6>() as u32) != 0 {
            if errno().0 != EINPROGRESS {
                return ConnectionError::Error;
            }
        } else {
            return rexmpp_tcp_connected(conn,
                                        (*conn).sockets[(*conn).connection_attempts as usize]);
        }
        (*conn).connection_attempts += 1;
        return ConnectionError::InProgress;
    }
    (*conn).resolution_v4 = ResolutionStatus::Waiting;
    (*conn).resolution_v6 = ResolutionStatus::Waiting;

    rexmpp_dns::rexmpp_dns_resolve(s, host, 28, 1,
                                   conn as *mut c_void,
                                   rexmpp_tcp_dns_aaaa_cb);
    rexmpp_dns::rexmpp_dns_resolve(s, host, 1, 1,
                                   conn as *mut c_void,
                                   rexmpp_tcp_dns_a_cb);
    return ConnectionError::InProgress;
}

#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_conn_finish (conn: *mut RexmppTCPConnection) -> c_int {
  rexmpp_tcp_cleanup(conn);
  return (*conn).fd;
}

#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_conn_ipv4_available (conn: *mut RexmppTCPConnection) -> bool {
    (*conn).resolution_v4 == ResolutionStatus::Success
        && (*conn).resolved_v4 != null_mut()
        && *(*(*conn).resolved_v4).data
        .offset(((*conn).addr_cur_v4 + 1) as isize) != null_mut()
}

#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_conn_ipv6_available (conn: *mut RexmppTCPConnection) -> bool {
    (*conn).resolution_v6 == ResolutionStatus::Success
        && (*conn).resolved_v6 != null_mut()
        && *(*(*conn).resolved_v6).data
        .offset(((*conn).addr_cur_v6 + 1) as isize) != null_mut()
}

#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_conn_proceed (s: *mut rexmpp::Rexmpp,
                            conn: *mut RexmppTCPConnection,
                            read_fds: *mut fd_set,
                            write_fds: *mut fd_set) -> ConnectionError {
    // Check for successful connections.
    for i in 0..=(REXMPP_TCP_MAX_CONNECTION_ATTEMPTS - 1) {
        if (*conn).sockets[i] != -1 && FD_ISSET((*conn).sockets[i], write_fds) {
            let mut err: c_int = 0;
            let mut err_len: socklen_t = mem::size_of::<c_int>() as u32;
            if getsockopt((*conn).sockets[i], SOL_SOCKET, SO_ERROR,
                          &mut err as *mut c_int as *mut c_void,
                          &mut err_len) < 0 {
                return ConnectionError::Error;
            } else {
                if err == 0 {
                    return rexmpp_tcp_connected(conn, (*conn).sockets[i]);
                } else if err != EINPROGRESS {
                    close((*conn).sockets[i]);
                    (*conn).sockets[i] = -1;
                }
            }
        }
    }

    // Name resolution
    if (*conn).resolution_v4 == ResolutionStatus::Waiting
        || (*conn).resolution_v6 == ResolutionStatus::Waiting {
            rexmpp_dns::rexmpp_dns_process(s, read_fds, write_fds);
        }
    if (*conn).resolution_v4 == ResolutionStatus::Failure
        && (*conn).resolution_v6 == ResolutionStatus::Failure {
            // Failed to resolve anything
            return ConnectionError::Failure;
        }

    // New connections
    let mut repeat: bool;
    let mut now = mem::MaybeUninit::<timespec>::uninit();
    let now_ptr = now.as_mut_ptr();
    loop {
        repeat = false;
        if (*conn).connection_attempts < REXMPP_TCP_MAX_CONNECTION_ATTEMPTS as i32
            && (rexmpp_tcp_conn_ipv4_available(conn)
                || rexmpp_tcp_conn_ipv6_available(conn)) {
                clock_gettime(CLOCK_MONOTONIC, now_ptr);
                if (*now_ptr).tv_sec > (*conn).next_connection_time.tv_sec
                    || ((*now_ptr).tv_sec == (*conn).next_connection_time.tv_sec
                        && (*now_ptr).tv_nsec >= (*conn).next_connection_time.tv_nsec) {
                        // Time to attempt a new connection
                        let mut use_ipv6 = false;
                        if rexmpp_tcp_conn_ipv4_available(conn) &&
                            rexmpp_tcp_conn_ipv6_available(conn) {
                                if (*conn).addr_cur_v4 >= (*conn).addr_cur_v6 {
                                    use_ipv6 = true;
                                }
                            } else if rexmpp_tcp_conn_ipv6_available(conn) {
                                use_ipv6 = true;
                            }

                        let addr: *mut sockaddr;
                        let addrlen: socklen_t;
                        let domain: c_int;
                        if use_ipv6 {
                            let mut addr_v6: sockaddr_in6 = mem::zeroed();
                            (*conn).addr_cur_v6 += 1;
                            let len = (mem::size_of::<in6_addr>() as i32)
                                .min(*(*(*conn).resolved_v6).len.offset((*conn).addr_cur_v6 as isize));
                            memcpy(&mut addr_v6.sin6_addr as *mut in6_addr as *mut c_void,
                                   *(*(*conn).resolved_v6).data.offset((*conn).addr_cur_v6 as isize),
                                   len as usize);
                            addr_v6.sin6_family = AF_INET6 as u16;
                            addr_v6.sin6_port = (*conn).port.to_be();
                            addr_v6.sin6_flowinfo = 0;
                            addr_v6.sin6_scope_id = 0;
                            domain = AF_INET6;
                            addr = &mut addr_v6 as *mut sockaddr_in6 as *mut sockaddr;
                            addrlen = mem::size_of::<sockaddr_in6>() as u32;
                        } else {
                            let mut addr_v4: sockaddr_in = mem::zeroed();
                            (*conn).addr_cur_v4 += 1;
                            let len = (mem::size_of::<in_addr>() as i32)
                                .min(*(*(*conn).resolved_v4).len.offset((*conn).addr_cur_v4 as isize));
                            memcpy(&mut addr_v4.sin_addr as *mut in_addr as *mut c_void,
                                   *(*(*conn).resolved_v4).data.offset((*conn).addr_cur_v4 as isize),
                                   len as usize);
                            addr_v4.sin_family = AF_INET as u16;
                            addr_v4.sin_port = (*conn).port.to_be();
                            domain = AF_INET;
                            addr = &mut addr_v4 as *mut sockaddr_in as *mut sockaddr;
                            addrlen = mem::size_of::<sockaddr_in>() as u32;
                        }
                        (*conn).sockets[(*conn).connection_attempts as usize] =
                            rexmpp_tcp_socket(s, domain);
                        if connect((*conn).sockets[(*conn).connection_attempts as usize],
                                   addr, addrlen) != 0 {
                            if errno().0 == EINPROGRESS {
                                clock_gettime(CLOCK_MONOTONIC, &mut (*conn).next_connection_time);
                                (*conn).next_connection_time.tv_nsec +=
                                    REXMPP_TCP_CONN_DELAY_MS * 1000000;
                                if (*conn).next_connection_time.tv_nsec >= 1000000000 {
                                    (*conn).next_connection_time.tv_nsec -= 1000000000;
                                    (*conn).next_connection_time.tv_sec += 1;
                                }
                                (*conn).connection_attempts += 1;
                            } else {
                                close((*conn).sockets[(*conn).connection_attempts as usize]);
                                (*conn).sockets[(*conn).connection_attempts as usize] = -1;
                                if (*conn).connection_attempts < REXMPP_TCP_MAX_CONNECTION_ATTEMPTS as i32
                                    && (rexmpp_tcp_conn_ipv4_available(conn) ||
                                        rexmpp_tcp_conn_ipv6_available(conn)) {
                                    repeat = true;
                                }
                            }
                        } else {
                            return rexmpp_tcp_connected(conn,
                                                        (*conn).sockets[(*conn).connection_attempts as usize]);
                        }
                    }
            }
        if ! repeat {
            break;
        }
    }

    let mut active_connections = false;
    for i in 0..=(REXMPP_TCP_MAX_CONNECTION_ATTEMPTS - 1) {
        if (*conn).sockets[i] != -1 {
            active_connections = true;
            break;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, now_ptr);

    if active_connections
        || (*conn).resolution_v4 == ResolutionStatus::Waiting
        || (*conn).resolution_v6 == ResolutionStatus::Waiting
        || ((*conn).next_connection_time.tv_sec > (*now_ptr).tv_sec
            || ((*conn).next_connection_time.tv_sec == (*now_ptr).tv_sec
                && (*conn).next_connection_time.tv_nsec > (*now_ptr).tv_nsec)) {
            ConnectionError::InProgress
        } else {
            ConnectionError::Failure
        }
}

#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_conn_fds (s: *mut rexmpp::Rexmpp,
                        conn: *mut RexmppTCPConnection,
                        read_fds: *mut fd_set,
                        write_fds: *mut fd_set) -> c_int {
    let mut max_fd: c_int = 0;
    if (*conn).resolution_v4 == ResolutionStatus::Waiting
        || (*conn).resolution_v6 == ResolutionStatus::Waiting {
            max_fd = rexmpp_dns::rexmpp_dns_fds(s, read_fds, write_fds);
        }
    for i in 0..=(REXMPP_TCP_MAX_CONNECTION_ATTEMPTS - 1) {
        if (*conn).sockets[i] != -1 {
            FD_SET((*conn).sockets[i], write_fds);
            if max_fd < (*conn).sockets[i] + 1 {
                max_fd = (*conn).sockets[i] + 1;
            }
        }
    }
    max_fd
}

#[no_mangle]
unsafe extern "C"
fn rexmpp_tcp_conn_timeout (s: *mut rexmpp::Rexmpp,
                            conn: *mut RexmppTCPConnection,
                            max_tv: *mut timespec,
                            tv: *mut timespec) -> *mut timespec {
    let mut now: timespec = mem::zeroed();
    let mut ret: *mut timespec = max_tv;
    if (*conn).resolution_v4 == ResolutionStatus::Waiting
        || (*conn).resolution_v6 == ResolutionStatus::Waiting {
            ret = rexmpp_dns::rexmpp_dns_timeout(s, max_tv, tv);
        }
    if (*conn).resolution_v4 == ResolutionStatus::Success
        || (*conn).resolution_v6 == ResolutionStatus::Success
        || ((*conn).resolution_v4 == ResolutionStatus::Inactive
            && (*conn).resolution_v4 == ResolutionStatus::Inactive) {
            clock_gettime(CLOCK_MONOTONIC, &mut now);
            if now.tv_sec < (*conn).next_connection_time.tv_sec
                || (now.tv_sec == (*conn).next_connection_time.tv_sec
                    && now.tv_nsec <= (*conn).next_connection_time.tv_nsec) {
                    if ret == null_mut()
                        || (*ret).tv_sec > (*conn).next_connection_time.tv_sec - now.tv_sec
                        || ((*ret).tv_sec == (*conn).next_connection_time.tv_sec - now.tv_sec
                            && (*ret).tv_nsec > (*conn).next_connection_time.tv_nsec - now.tv_sec) {
                            ret = tv;
                            (*tv).tv_sec = (*conn).next_connection_time.tv_sec - now.tv_sec;
                            if (*conn).next_connection_time.tv_nsec > now.tv_nsec {
                                (*tv).tv_nsec = (*conn).next_connection_time.tv_nsec - now.tv_nsec;
                            } else {
                                (*tv).tv_nsec = (*conn).next_connection_time.tv_nsec + 1000000000 - now.tv_nsec;
                                (*tv).tv_sec -= 1;
                            }
                        }
                }
        }
    ret
}
