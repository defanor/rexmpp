// For rustc and libstd-rust version 1.48

use std::os::raw::{c_int, c_char};
use std::ffi::CStr;
use std::net::TcpStream;
use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::io::Write;
use std::io::Read;
use std::io::ErrorKind;
use std::convert::TryFrom;

const REXMPP_SOCKS_BUF_LEN: usize = 300;

#[derive(PartialEq)]
#[repr(C)]
enum SocksIOState {
    Writing,
    Reading
}

#[derive(PartialEq)]
#[repr(C)]
enum SocksStage {
    Auth,
    Cmd,
    Done
}

#[derive(PartialEq)]
#[repr(C)]
enum SocksErr {
    Connected,
    EAgain,
    ETCP,
    EReply,
    EVersion,
    ESocks,
    EHost
}

#[repr(C)]
pub struct RexmppSocks {
    fd: c_int,
    host: *const c_char,
    port: u16,
    stage: SocksStage,
    io_state: SocksIOState,
    socks_error: c_int,
    buf: [u8; REXMPP_SOCKS_BUF_LEN],
    buf_len: usize,
    buf_sent: usize
}

#[no_mangle]
extern "C" fn rexmpp_socks_proceed (s : &mut RexmppSocks) -> SocksErr {
    if s.io_state == SocksIOState::Writing {
        let mut stream : TcpStream = unsafe { TcpStream::from_raw_fd(s.fd) };
        let ret = stream.write(&s.buf[s.buf_sent .. s.buf_len]);
        // Make sure the connection is not closed by TcpStream.
        TcpStream::into_raw_fd(stream);
        match ret {
            Ok(sent) => {
                s.buf_sent += sent;
                if s.buf_len == s.buf_sent {
                    s.buf_len = 0;
                    s.io_state = SocksIOState::Reading;
                }
            }
            Err(error) => match error.kind() {
                ErrorKind::WouldBlock => return SocksErr::EAgain,
                _ => return SocksErr::ETCP
            }
        }
    } else if s.io_state == SocksIOState::Reading {
        let mut stream : TcpStream = unsafe { TcpStream::from_raw_fd(s.fd) };
        let ret = stream.read(&mut s.buf[s.buf_len ..]);
        // Make sure the connection is not closed by TcpStream.
        TcpStream::into_raw_fd(stream);
        match ret {
            Ok(received) => {
                s.buf_len += received;
                if s.buf[0] != 5 {
                    return SocksErr::EVersion;
                }
                if s.buf_len >= 2 {
                    s.socks_error = s.buf[1].into();
                }
                if s.stage == SocksStage::Auth {
                    if s.buf_len > 2 {
                        return SocksErr::EReply;
                    }
                    if s.buf_len == 2 {
                        if s.socks_error != 0 {
                            return SocksErr::ESocks;
                        }
                        s.buf[0] = 5; // SOCKS version 5
                        s.buf[1] = 1; // Connect
                        s.buf[2] = 0; // Reserved
                        s.buf[3] = 3; // Domain name (todo: IP addresses)
                        let host_cstr : &CStr =
                            unsafe { CStr::from_ptr(s.host) };
                        let host_len = host_cstr.to_bytes().len();
                        match u8::try_from(host_len) {
                            Ok(u) => { s.buf[4] = u }
                            Err(_) => return SocksErr::EHost
                        }
                        s.buf[5 .. 5 + host_len].
                            copy_from_slice(&host_cstr.to_bytes());
                        s.buf[5 + host_len .. 7 + host_len].
                            copy_from_slice(&s.port.to_be_bytes());
                        s.buf_len = 7 + host_len;
                        s.buf_sent = 0;
                        s.stage = SocksStage::Cmd;
                        s.io_state = SocksIOState::Writing;
                        return rexmpp_socks_proceed(s);
                    }
                } else if s.stage == SocksStage::Cmd {
                    if s.buf_len >= 5 {
                        let mut full_len : usize = 6;
                        match s.buf[3] {
                            // IPv4
                            1 => full_len += 4,
                            // Domain name
                            3 => full_len += usize::from(s.buf[4]) + 1,
                            // IPv6
                            4 => full_len += 16,
                            _ => return SocksErr::EReply
                        }
                        if s.buf_len > full_len {
                            return SocksErr::EReply;
                        }
                        if s.buf_len == full_len {
                            if s.socks_error != 0 {
                                return SocksErr::ESocks;
                            }
                            // We are done
                            s.stage = SocksStage::Done;
                            return SocksErr::Connected;
                        }
                    }
                }
            }
            Err(error) => match error.kind() {
                ErrorKind::WouldBlock => return SocksErr::EAgain,
                _ => return SocksErr::ETCP
            }
        }
    }
    return SocksErr::EAgain
}

#[no_mangle]
extern "C" fn rexmpp_socks_init (
    s : &mut RexmppSocks,
    fd: c_int,
    host: *const c_char,
    port: u16
)
    -> SocksErr
{
    s.fd = fd;
    s.host = host;
    s.port = port;
    s.socks_error = 0;

    let host_cstr : &CStr = unsafe { CStr::from_ptr(host) };
    if host_cstr.to_bytes().len() > 255 {
        return SocksErr::EHost;
    }

    // Request authentication
    s.stage = SocksStage::Auth;
    s.io_state = SocksIOState::Writing;
    s.buf[0] = 5;               // SOCKS version 5
    s.buf[1] = 1;               // 1 supported method
    s.buf[2] = 0;               // No authentication required
    s.buf_len = 3;
    s.buf_sent = 0;
    return rexmpp_socks_proceed(s);
}
