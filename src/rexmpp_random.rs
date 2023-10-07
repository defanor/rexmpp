use std::os::raw::{c_char};

extern {
    pub fn rexmpp_random_id () -> *mut c_char;
}
