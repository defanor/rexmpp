extern crate libc;
extern crate rxml;
use libc::{free, strndup};
use std::ptr;
use std::os::raw::{c_char, c_void};
use std::ffi::{CStr, CString};
use std::slice;
use rxml::{FeedParser, Error, ResolvedEvent, XmlVersion, EventRead, CData};
use std::io;
use std::sync::Arc;
use super::{rexmpp_xml};

type RexmppXMLParserElementStart = unsafe extern "C"
fn (data: *mut c_void,
    name: *const c_char,
    namespace: *const c_char,
    attributes: *mut rexmpp_xml::RexmppXMLAttribute) -> ();

type RexmppXMLParserElementEnd = unsafe extern "C"
fn (data: *mut c_void) -> ();

type RexmppXMLParserCharacters = unsafe extern "C"
fn (data: *mut c_void,
    ch: *const c_char,
    len: usize) -> ();

#[repr(C)]
struct RexmppXMLParserHandlers {
    elem_start: RexmppXMLParserElementStart,
    elem_end: RexmppXMLParserElementEnd,
    text: RexmppXMLParserCharacters
}

#[repr(C)]
struct RexmppXMLParserCtx {
    xml_parser: *mut FeedParser,
    handlers: *mut RexmppXMLParserHandlers,
    user_data: *mut c_void
}

#[no_mangle]
extern "C"
fn rexmpp_xml_parser_new (handlers: *mut RexmppXMLParserHandlers,
                          data: *mut c_void)
                          -> *mut RexmppXMLParserCtx
{
    let mut fp = FeedParser::default();
    let ctx = RexmppXMLParserCtx {
        xml_parser: Box::into_raw(Box::new(fp)),
        handlers: handlers,
        user_data: data
    };
    Box::into_raw(Box::new(ctx))
}

#[no_mangle]
extern "C"
fn rexmpp_xml_parser_free (ctx: *mut RexmppXMLParserCtx) {
    unsafe { free(ctx as *mut c_void) };
}

#[no_mangle]
extern "C"
fn rexmpp_xml_parser_feed (ctx: *mut RexmppXMLParserCtx,
                           chunk: *const c_char,
                           len: usize,
                           is_final: bool)
{
    unsafe {
        // todo: maybe duplicate the string, since apparently a
        // mutable one is expected by the parser.
        let mut buf : &[u8] = slice::from_raw_parts(chunk as *mut u8, len);
        let user_data_ptr = (*ctx).user_data;
        let handlers = (*ctx).handlers;
        (*((*ctx).xml_parser)).parse_all(&mut buf, is_final, |ev| {
            match ev {
                ResolvedEvent::StartElement(_, (namespace, name), attrs) =>
                {
                    let name_str = name.to_string();
                    let ns_opt_cstr : Option<CString> = match namespace {
                        None => None,
                        Some(ns_arc_name) => {
                            match CString::new(ns_arc_name.to_string()) {
                                Ok(cstr) => Some(cstr),
                                Err(_) => None
                            }
                        }
                    };
                    match CString::new(name_str) {
                        Ok(name_cstr) => {
                            let name_cstr_ptr = name_cstr.as_ptr();
                            let namespace_cstr_ptr =
                                match ns_opt_cstr {
                                    None => ptr::null_mut(),
                                    // "ref" is important to use here,
                                    // otherwise the pointer will be
                                    // wrong.
                                    Some(ref ns_cstr) => ns_cstr.as_ptr()
                                };
                            let mut attributes = ptr::null_mut();
                            for ((_, attr_name), attr_val) in attrs.iter() {
                                match (CString::new(attr_name.to_string()),
                                       CString::new(attr_val.to_string())) {
                                    (Ok(attr_name_cstr), Ok(attr_val_cstr)) => {
                                        let attr =
                                            rexmpp_xml::rexmpp_xml_attr_new
                                            (attr_name_cstr.as_ptr(),
                                             ptr::null_mut(),
                                             attr_val_cstr.as_ptr());
                                        (*attr).next = attributes;
                                        attributes = attr;
                                    },
                                    _ => ()
                                }
                            }
                            ((*handlers).elem_start)
                                (user_data_ptr,
                                 name_cstr_ptr,
                                 namespace_cstr_ptr,
                                 attributes);
                        },
                        Err(_) => ()
                    }
                },
                ResolvedEvent::EndElement(_) =>
                    ((*handlers).elem_end)(user_data_ptr),
                ResolvedEvent::Text(_, cd) =>
                    ((*handlers).text)(
                        user_data_ptr,
                        cd.as_ptr() as *const i8,
                        cd.len()
                    ),
                _ => ()
            }
        });
    }
}

#[no_mangle]
extern "C"
fn rexmpp_xml_parser_reset (ctx_raw: *mut RexmppXMLParserCtx)
                            -> *mut RexmppXMLParserCtx
{
    let ctx = unsafe { Box::from_raw(ctx_raw) };
    rexmpp_xml_parser_new((*ctx).handlers, (*ctx).user_data)
}
