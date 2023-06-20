use std::os::raw::{c_char};

#[repr(C)]
pub struct RexmppJID {
    local: [c_char; 1024],
    domain: [c_char; 1024],
    resource: [c_char; 1024],
    bare: [c_char; 2048],
    full: [c_char; 3072]
}

// #[no_mangle]
// extern "C"
// fn rexmpp_jid_parse (str: *const c_char, jid : &mut RexmppJID) -> c_int
// {

// }
