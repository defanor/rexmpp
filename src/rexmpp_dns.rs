use std::os::raw::{c_int, c_void, c_char};
use libc::*;
use std::ptr;

use super::rexmpp;

type DNSQueryCB = unsafe extern "C"
fn (s: *mut rexmpp::Rexmpp, ptr: *mut c_void, result: *mut RexmppDNSResult) -> ();

extern {
    pub fn rexmpp_dns_resolve (s: *mut rexmpp::Rexmpp,
                               query: *const c_char,
                               rrtype: c_int,
                               rrclass: c_int,
                               ptr: *mut c_void,
                               callback: DNSQueryCB) -> c_int;
    pub fn rexmpp_dns_process (s: *mut rexmpp::Rexmpp,
                               read_fds: *mut fd_set,
                               write_fds: *mut fd_set) -> c_int;
    pub fn rexmpp_dns_fds (s: *mut rexmpp::Rexmpp,
                           read_fds: *mut fd_set,
                           write_fds: *mut fd_set) -> c_int;
    pub fn rexmpp_dns_timeout (s: *mut rexmpp::Rexmpp,
                               max_tv: *mut timespec,
                               tv: *mut timespec) -> *mut timespec;
}

#[repr(C)]
pub struct RexmppDNSResult {
    pub data: *mut *mut c_void,
    pub len: *mut c_int,
    pub secure: bool
}

#[repr(C)]
pub struct RexmppDNSSRV {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: [c_char; 256]
}


#[no_mangle]
pub unsafe extern "C"
fn rexmpp_dns_result_free (result: *mut RexmppDNSResult) {
    if (*result).data != ptr::null_mut() {
        let mut i = 0;
        let data_ptr: *mut *mut c_void = (*result).data;
        while *(data_ptr.offset(i)) != ptr::null_mut() {
            free(*(data_ptr.offset(i)));
            i += 1;
        }
        free((*result).data as *mut c_void);
        (*result).data = ptr::null_mut();
    }
    if (*result).len != ptr::null_mut() {
        free((*result).len as *mut c_void);
        (*result).len = ptr::null_mut();
    }
    free(result as *mut c_void);
}
