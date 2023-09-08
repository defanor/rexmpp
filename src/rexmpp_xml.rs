extern crate libc;
use libc::{strdup, strndup, free, strcmp};
use std::os::raw::{c_char, c_int, c_void, c_uint};
use std::ptr;
use std::ffi::{CStr, CString};
use std::clone::Clone;
use std::fs::File;
use std::io::Write;

use super::{rexmpp};

// extern {
//     fn rexmpp_xml_parse (str: *mut c_char, str_len: c_int) -> *mut RexmppXML;
// }

#[repr(C)]
pub struct RexmppXMLQName {
    name: *mut c_char,
    namespace: *mut c_char
}

impl Copy for RexmppXMLQName { }

impl Clone for RexmppXMLQName {
    fn clone(&self) -> RexmppXMLQName {
        RexmppXMLQName {
            name: unsafe { strdup(self.name) },
            namespace: if self.namespace != ptr::null_mut() {
                unsafe { strdup(self.namespace) }
            } else {
                ptr::null_mut()
            }
        }
    }
}

#[repr(C)]
pub struct RexmppXMLAttribute {
    qname: RexmppXMLQName,
    value: *mut c_char,
    next: *mut RexmppXMLAttribute
}

impl Copy for RexmppXMLAttribute { }

impl Clone for RexmppXMLAttribute {
    fn clone(&self) -> RexmppXMLAttribute {
        RexmppXMLAttribute {
            qname: Clone::clone(&self.qname),
            value: unsafe { strdup(self.value) },
            next: ptr::null_mut()
        }
    }
}

#[derive(Copy, Clone)]
#[derive(PartialEq)]
#[repr(C)]
enum NodeType {
    Element,
    Text
}

#[repr(C)]
struct RexmppXMLAltElem {
    qname: RexmppXMLQName,
    attributes: *mut RexmppXMLAttribute,
    children: *mut RexmppXML
}

impl Copy for RexmppXMLAltElem { }

impl Clone for RexmppXMLAltElem {
    fn clone(&self) -> RexmppXMLAltElem {
        let mut ret = RexmppXMLAltElem {
            qname: Clone::clone(&self.qname),
            attributes: ptr::null_mut(),
            children: ptr::null_mut()
        };
        let mut old_attr_ptr = self.attributes;
        let mut next_attr_ptr_ptr : *mut *mut RexmppXMLAttribute = &mut ret.attributes;
        loop {
            match unsafe { old_attr_ptr.as_mut() } {
                None => break,
                Some(old_attr) => {
                    let new_attr_ptr = rexmpp_xml_attr_new(old_attr.qname.name,
                                                           old_attr.qname.namespace,
                                                           old_attr.value);
                    unsafe { next_attr_ptr_ptr.write(new_attr_ptr) };
                    next_attr_ptr_ptr = unsafe { &mut ((*new_attr_ptr).next) };
                    old_attr_ptr = old_attr.next;
                }
            }
        }
        ret.children = rexmpp_xml_clone_list(self.children);
        return ret;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
union RexmppXMLAlt {
    elem: RexmppXMLAltElem,
    text: *mut c_char
}

#[repr(C)]
pub struct RexmppXML {
    node_type: NodeType,
    alt: RexmppXMLAlt,
    next: *mut RexmppXML
}

impl Copy for RexmppXML { }

impl Clone for RexmppXML {
    fn clone(&self) -> RexmppXML {
        RexmppXML {
            node_type: Clone::clone(&self.node_type),
            alt: match self.node_type {
                NodeType::Text => RexmppXMLAlt
                { text: unsafe { strdup(self.alt.text) }},
                NodeType::Element => RexmppXMLAlt
                { elem: Clone::clone(& unsafe { self.alt.elem }) }
            },
            next: ptr::null_mut()
        }
    }
}

#[no_mangle]
extern "C"
fn rexmpp_xml_qname_free (qname_ptr: *mut RexmppXMLQName) {
    match unsafe { qname_ptr.as_mut() } {
        None => return,
        Some(qname) => {
            if qname.name != ptr::null_mut() {
                unsafe { free(qname.name as *mut c_void) };
                qname.name = ptr::null_mut();
            }
            if qname.namespace != ptr::null_mut() {
                unsafe { free(qname.namespace as *mut c_void) };
                qname.namespace = ptr::null_mut();
            }
        }
    }
}

#[no_mangle]
extern "C"
fn rexmpp_xml_attribute_free (attr_ptr: *mut RexmppXMLAttribute) {
    if attr_ptr == ptr::null_mut() {
        return;
    }
    let mut attr : RexmppXMLAttribute = unsafe { *Box::from_raw(attr_ptr) };
    rexmpp_xml_qname_free(&mut (attr.qname));
    if attr.value != ptr::null_mut() {
        unsafe { free(attr.value as *mut c_void) }
        attr.value = ptr::null_mut();
    }
}

#[no_mangle]
extern "C"
fn rexmpp_xml_attribute_free_list (mut attr_ptr: *mut RexmppXMLAttribute) {
    let mut next;
    while attr_ptr != ptr::null_mut() {
        next = unsafe { (*attr_ptr).next };
        rexmpp_xml_attribute_free(attr_ptr);
        attr_ptr = next;
    }
}

#[no_mangle]
extern "C"
fn rexmpp_xml_free (node_ptr: *mut RexmppXML) {
    if node_ptr == ptr::null_mut() {
        return;
    }
    let mut node : RexmppXML = unsafe { *Box::from_raw(node_ptr) };
    unsafe {
        match node {
            RexmppXML { node_type : NodeType::Text,
                        alt : RexmppXMLAlt { text: text_ptr },
                        next: _} => {
                free(text_ptr as *mut c_void);
                node.alt.text = ptr::null_mut();
            },
            RexmppXML { node_type : NodeType::Element,
                        alt : RexmppXMLAlt { elem: mut element },
                        next: _} => {
                rexmpp_xml_qname_free(&mut (element.qname));
                rexmpp_xml_attribute_free_list(element.attributes);
                rexmpp_xml_free_list(element.children);
            }
        }
    }
}

#[no_mangle]
extern "C"
fn rexmpp_xml_free_list (mut node_ptr: *mut RexmppXML) {
    let mut next;
    while node_ptr != ptr::null_mut() {
        next = unsafe { (*node_ptr).next };
        rexmpp_xml_free(node_ptr);
        node_ptr = next;
    }
}

#[no_mangle]
extern "C"
fn rexmpp_xml_clone (node_ptr: *mut RexmppXML) -> *mut RexmppXML {
    if node_ptr == ptr::null_mut() {
        return ptr::null_mut();
    }
    return Box::into_raw(Box::new(Clone::clone(& unsafe { *node_ptr })));
}

#[no_mangle]
extern "C"
fn rexmpp_xml_clone_list (mut node_ptr: *mut RexmppXML) -> *mut RexmppXML {
    if node_ptr == ptr::null_mut() {
        return ptr::null_mut();
    }
    let first_ptr = rexmpp_xml_clone(node_ptr);
    let mut last_ptr = first_ptr;
    node_ptr = unsafe { (*node_ptr).next };
    while node_ptr != ptr::null_mut() {
        unsafe { (*last_ptr).next = rexmpp_xml_clone(node_ptr) };
        last_ptr = unsafe { (*last_ptr).next };
        node_ptr = unsafe { (*node_ptr).next };
    }
    return first_ptr;
}


#[no_mangle]
extern "C"
fn rexmpp_xml_new_text (str: *const c_char) -> *mut RexmppXML {
    let node = RexmppXML {
        node_type: NodeType::Text,
        alt: RexmppXMLAlt { text: unsafe { strdup(str) } },
        next: ptr::null_mut()
    };
    let b = Box::new(node);
    return Box::into_raw(b);
}

#[no_mangle]
extern "C"
fn rexmpp_xml_new_text_len (str: *const c_char, len: usize) -> *mut RexmppXML {
    let node = RexmppXML {
        node_type: NodeType::Text,
        alt: RexmppXMLAlt { text: unsafe { strndup(str, len) } },
        next: ptr::null_mut()
    };
    let b = Box::new(node);
    return Box::into_raw(b);
}

#[no_mangle]
extern "C" fn rexmpp_xml_add_child (node: *mut RexmppXML,
                                    child: *mut RexmppXML) -> () {
    let mut last_ptr : &mut *mut RexmppXML =
        unsafe { &mut ((*node).alt.elem.children) };
    while *last_ptr != ptr::null_mut() {
        last_ptr = unsafe { &mut ((*(* last_ptr)).next) };
    }
    *last_ptr = child;
}

#[no_mangle]
extern "C" fn rexmpp_xml_add_text (node: *mut RexmppXML,
                                   str: *const c_char) -> c_int {
    let text_node : *mut RexmppXML = rexmpp_xml_new_text(str);
    if text_node != ptr::null_mut() {
        rexmpp_xml_add_child(node, text_node);
        return 1;
    }
    return 0;
}

#[no_mangle]
extern "C" fn rexmpp_xml_add_text_len (node: *mut RexmppXML,
                                       str: *const c_char,
                                       len: usize) -> c_int {
    let text_node : *mut RexmppXML = rexmpp_xml_new_text_len(str, len);
    if text_node != ptr::null_mut() {
        rexmpp_xml_add_child(node, text_node);
        return 1;
    }
    return 0;
}

#[no_mangle]
extern "C"
fn rexmpp_xml_new_elem (name: *const c_char,
                        namespace: *const c_char) -> *mut RexmppXML {
    let node = RexmppXML {
        node_type: NodeType::Element,
        alt: RexmppXMLAlt {
            elem: RexmppXMLAltElem {
                qname: RexmppXMLQName {
                    name: unsafe { strdup(name) },
                    namespace: if namespace == ptr::null_mut() {
                        ptr::null_mut()
                    } else {
                        unsafe { strdup(namespace) }
                    }
                },
                attributes: ptr::null_mut(),
                children: ptr::null_mut()
            }
        },
        next: ptr::null_mut()
    };
    let b = Box::new(node);
    return Box::into_raw(b);
}

#[no_mangle]
extern "C"
fn rexmpp_xml_attr_new (name: *const c_char,
                        namespace: *const c_char,
                        value: *const c_char) -> *mut RexmppXMLAttribute {
    let node = RexmppXMLAttribute {
        qname: RexmppXMLQName {
            name: unsafe { strdup(name) },
            namespace: if namespace == ptr::null_mut() {
                ptr::null_mut()
            } else {
                unsafe { strdup(namespace) }
            }
        },
        value: unsafe { strdup(value) },
        next: ptr::null_mut()
    };
    return Box::into_raw(Box::new(node));
}

#[no_mangle]
extern "C"
fn rexmpp_xml_add_attr_ns (node: *mut RexmppXML,
                           name: *const c_char,
                           namespace: *const c_char,
                           value: *const c_char) -> c_int {
    if node == ptr::null_mut()
        || unsafe { (*node).node_type } != NodeType::Element {
            return -1;
        }
    let attr = rexmpp_xml_attr_new(name, namespace, value);
    unsafe {
        (*attr).next = (*node).alt.elem.attributes;
        (*node).alt.elem.attributes = attr;
    }
    return 0;
}

#[no_mangle]
extern "C"
fn rexmpp_xml_remove_attr_ns (node: *mut RexmppXML,
                              name: *const c_char,
                              namespace: *const c_char) -> c_int {
    if node == ptr::null_mut()
        || unsafe { (*node).node_type } != NodeType::Element {
            return -1;
        }
    let mut attr_ptr_ptr: *mut *mut RexmppXMLAttribute =
        unsafe { &mut (*node).alt.elem.attributes };
    while unsafe { *attr_ptr_ptr } != ptr::null_mut() {
        if rexmpp_xml_attr_match(unsafe { *attr_ptr_ptr }, namespace, name) > 0 {
            let next_attr_ptr : *mut RexmppXMLAttribute =
                unsafe { (**attr_ptr_ptr).next };
            rexmpp_xml_attribute_free(unsafe { *attr_ptr_ptr });
            unsafe { *attr_ptr_ptr = next_attr_ptr }
            return 0;
        }
        attr_ptr_ptr = unsafe { &mut (**attr_ptr_ptr).next };
    }
    return 1;
}

#[no_mangle]
extern "C"
fn rexmpp_xml_add_attr (node: *mut RexmppXML,
                        name: *const c_char,
                        value: *const c_char) -> c_int {
    rexmpp_xml_add_attr_ns(node, name, ptr::null_mut(), value)
}

#[no_mangle]
extern "C"
fn rexmpp_xml_remove_attr (node: *mut RexmppXML,
                           name: *const c_char) -> c_int {
    rexmpp_xml_remove_attr_ns(node, name, ptr::null_mut())
}


fn rexmpp_xml_push_escaped (c: char, s: &mut String) {
    if c == '<' {
        s.push_str("&lt;")
    } else if c == '>' {
        s.push_str("&gt;")
    } else if c == '&' {
        s.push_str("&amp;")
    } else if c == '\'' {
        s.push_str("&apos;")
    } else if c == '"' {
        s.push_str("&quot;")
    } else {
        s.push_str(format!("&#{};", u32::from(c)).as_str());
    };
}

fn rexmpp_xml_print_text (c: char, s: &mut String) {
    if "<&>'\"".chars().any(|sc| sc == c) {
        rexmpp_xml_push_escaped(c, s);
    } else {
        s.push(c);
    }
}

fn rexmpp_xml_print_name (i: usize, c: char, s: &mut String) {
    if c == ':'
        || (c >= 'A' && c <= 'Z')
        || c == '_'
        || (c >= 'a' && c <= 'z')
        || (c >= '\u{C0}' && c <= '\u{D6}')
        || (c >= '\u{D8}' && c <= '\u{F6}')
        || (c >= '\u{F8}' && c <= '\u{2FF}')
        || (c >= '\u{370}' && c <= '\u{37D}')
        || (c >= '\u{37F}' && c <= '\u{1FFF}')
        || (c >= '\u{200C}' && c <= '\u{200D}')
        || (c >= '\u{2070}' && c <= '\u{218F}')
        || (c >= '\u{2C00}' && c <= '\u{2FEF}')
        || (c >= '\u{3001}' && c <= '\u{D7FF}')
        || (c >= '\u{F900}' && c <= '\u{FDCF}')
        || (c >= '\u{FDF0}' && c <= '\u{FFF0}')
        || (c >= '\u{10000}' && c <= '\u{EFFFF}')
        || ((i > 0) &&
            (c == '-'
             || c == '.'
             || (c >= '0' && c <= '9')
             || c == '\u{B7}'
             || (c >= '\u{0300}' && c <= '\u{036F}')
             || (c >= '\u{203F}' && c <= '\u{2040}')))
    {
        // Print the allowed characters.
        s.push(c);
    }
}

fn rexmpp_xml_print_indent (indent: i32, s: &mut String) {
    let mut i = 0;
    while i < indent {
        s.push_str("  ");
        i = i + 1;
    }
}

fn rexmpp_xml_print (node_ptr: *const RexmppXML,
                     ret: &mut String,
                     indent: i32)
                     -> ()
{
    unsafe {
        let node : RexmppXML = *node_ptr;
        match node {
            RexmppXML { node_type : NodeType::Text,
                        alt : RexmppXMLAlt { text: text_ptr },
                        next: _} => {
                let text_cstr : &CStr = CStr::from_ptr(text_ptr);
                let text_str : String =
                    String::from_utf8_lossy(text_cstr.to_bytes())
                    .to_string();
                // let mut escaped = String::with_capacity(text_str.capacity());
                text_str.chars().
                    for_each(|c| rexmpp_xml_print_text(c, ret));
            },
            RexmppXML { node_type : NodeType::Element,
                        alt : RexmppXMLAlt { elem: element },
                        next: _} => {
                // let mut ret = String::with_capacity(1024);
                let name_cstr : &CStr =
                    CStr::from_ptr(element.qname.name);
                let name_str : String =
                    String::from_utf8_lossy(name_cstr.to_bytes())
                    .to_string();
                if indent > 0 {
                    ret.push('\n');
                    rexmpp_xml_print_indent(indent, ret);
                }
                ret.push('<');
                name_str.char_indices().
                    for_each(|(i, c)| rexmpp_xml_print_name(i, c, ret));
                if element.qname.namespace != ptr::null_mut() {
                    let namespace_cstr : &CStr =
                        CStr::from_ptr(element.qname.namespace);
                    let namespace_str : String =
                        String::from_utf8_lossy(namespace_cstr.to_bytes())
                        .to_string();
                    ret.push_str(" xmlns=\"");
                    namespace_str.chars().
                        for_each(|c| rexmpp_xml_print_text(c, ret));
                    ret.push('"');
                }
                if element.attributes != ptr::null_mut() {
                    let mut attr_ptr : *mut RexmppXMLAttribute =
                        element.attributes;
                    while attr_ptr != ptr::null_mut() {
                        let attr : RexmppXMLAttribute = *attr_ptr;
                        let attr_name_cstr =
                            CStr::from_ptr(attr.qname.name);
                        let attr_name_str =
                            String::from_utf8_lossy(attr_name_cstr.to_bytes())
                            .to_string();
                        // TODO: handle attribute namespaces someday.
                        let attr_value_cstr =
                            CStr::from_ptr(attr.value);
                        let attr_value_str =
                            String::from_utf8_lossy(attr_value_cstr.to_bytes())
                            .to_string();
                        ret.push(' ');
                        attr_name_str.char_indices().
                            for_each(|(i, c)|
                                     rexmpp_xml_print_name(i, c, ret));
                        ret.push_str("=\"");
                        attr_value_str.chars().
                            for_each(|c| rexmpp_xml_print_text(c, ret));
                        ret.push('"');
                        attr_ptr = (*attr_ptr).next;
                    }
                }
                if element.children == ptr::null_mut() {
                    ret.push_str("/>");
                } else {
                    ret.push('>');
                    let mut child = rexmpp_xml_children(node_ptr);
                    let mut last_child_is_textual = false;
                    while child != ptr::null_mut() {
                        rexmpp_xml_print(child, ret,
                                         if indent > -1 { indent + 1 }
                                         else { -1 } );
                        last_child_is_textual =
                            (*child).node_type == NodeType::Text;
                        child = (*child).next;
                    }
                    if indent > 0 && ! last_child_is_textual {
                        ret.push('\n');
                        rexmpp_xml_print_indent(indent, ret);
                    }
                    ret.push_str("</");
                    name_str.char_indices().
                        for_each(|(i, c)|
                                 rexmpp_xml_print_name(i, c, ret));
                    ret.push('>');
                }
            }
        }
    }
}

fn rexmpp_xml_serialize_str (node_ptr: *const RexmppXML,
                             pretty: bool)
                             -> String
{
    let mut out = String::with_capacity(4096);
    rexmpp_xml_print(node_ptr, &mut out, if pretty { 0 } else { -1 });
    return out;
}

#[no_mangle]
extern "C"
fn rexmpp_xml_serialize (node_ptr: *const RexmppXML,
                         pretty: bool)
                         -> *mut c_char
{
    let out = rexmpp_xml_serialize_str(node_ptr, pretty);
    match CString::new(out) {
        Ok(cstr) => unsafe { strdup(cstr.as_ptr()) },
        Err(_) => ptr::null_mut()
    }
}

#[no_mangle]
extern "C"
fn rexmpp_xml_add_id (s: *mut rexmpp::Rexmpp, node: *mut RexmppXML)
                      -> *mut RexmppXML
{
    match CString::new("id") {
        Err(_) => return ptr::null_mut(),
        Ok(id_cstr) => {
            let buf = unsafe { rexmpp::rexmpp_gen_id(s) };
            if buf == ptr::null_mut() {
                return ptr::null_mut();
            }
            rexmpp_xml_add_attr(node, id_cstr.as_ptr(), buf);
            unsafe { free(buf as *mut c_void) };
            return node;
        }
    }
}

#[no_mangle]
extern "C"
fn rexmpp_xml_write_file (path: *const c_char,
                          node: *const RexmppXML)
                          -> c_int
{
    let path_cstr : &CStr = unsafe { CStr::from_ptr(path) };
    let path_str : String =
        String::from_utf8_lossy(path_cstr.to_bytes())
        .to_string();
    match File::create(path_str) {
        Ok(mut fd) => {
            fd.write_all(b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
            fd.write_all(rexmpp_xml_serialize_str(node, false).as_bytes());
        },
        Err(_) => { return -1; }
    }
    return 0;
}

#[no_mangle]
extern "C"
fn rexmpp_xml_siblings_count (mut node: *const RexmppXML) -> c_uint {
    let mut i : c_uint = 0;
    while node != ptr::null() {
        node = unsafe { (*node).next };
        i = i + 1;
    }
    return i;
}

#[no_mangle]
extern "C"
fn rexmpp_xml_match (node_ptr: *const RexmppXML,
                     namespace: *const c_char,
                     name: *const c_char) -> c_int {
    if node_ptr == ptr::null_mut() {
        return 0;
    }
    let node : RexmppXML = unsafe { *node_ptr };
    if node.node_type != NodeType::Element {
        return 0;
    }
    if name != ptr::null_mut() {
        let name_cstr : &CStr = unsafe { CStr::from_ptr(name) };
        let elem_name_cstr : &CStr = unsafe { CStr::from_ptr(node.alt.elem.qname.name) };
        if name_cstr != elem_name_cstr {
            return 0;
        }
    }
    if namespace != ptr::null_mut() {
        let namespace_cstr : &CStr = unsafe { CStr::from_ptr(namespace) };
        if unsafe { node.alt.elem.qname.namespace } == ptr::null_mut() {
            match CStr::to_str(namespace_cstr) {
                Ok(namespace_str) => if namespace_str == "jabber:client" {
                    return 1;
                },
                Err(_) => return 0
            }
            return 0;
        }
        let elem_namespace_cstr : &CStr =
            unsafe { CStr::from_ptr(node.alt.elem.qname.namespace) };
        if namespace_cstr != elem_namespace_cstr {
            return 0;
        }
    }
    return 1;
}

#[no_mangle]
extern "C"
fn rexmpp_xml_attr_match (attr: *const RexmppXMLAttribute,
                          namespace: *const c_char,
                          name: *const c_char) -> c_int {
    if attr == ptr::null() {
        return 0;
    }
    if name != ptr::null() {
        let name_cstr : &CStr = unsafe { CStr::from_ptr(name) };
        let attr_name_cstr : &CStr = unsafe { CStr::from_ptr((*attr).qname.name) };
        if name_cstr != attr_name_cstr {
            return 0;
        }
    }
    if namespace != ptr::null() {
        let namespace_cstr : &CStr = unsafe { CStr::from_ptr(namespace) };
        if unsafe { (*attr).qname.namespace } == ptr::null_mut() {
            match CStr::to_str(namespace_cstr) {
                Ok(namespace_str) => if namespace_str != "jabber:client" {
                    return 0;
                },
                Err(_) => return 0
            }
        } else {
            let attr_namespace_cstr : &CStr =
                unsafe { CStr::from_ptr((*attr).qname.namespace) };
            if namespace_cstr != attr_namespace_cstr {
                return 0;
            }
        }
    }
    return 1;
}

#[no_mangle]
extern "C"
fn rexmpp_xml_is_stanza (node: *const RexmppXML) -> c_int {
    if rexmpp_xml_match(node,
                        CString::new("jabber:client").expect("CString::new failed").as_ptr(),
                        CString::new("message").expect("CString::new failed").as_ptr()) == 1
        || rexmpp_xml_match(node,
                            CString::new("jabber:client").expect("CString::new failed").as_ptr(),
                            CString::new("iq").expect("CString::new failed").as_ptr()) == 1
        || rexmpp_xml_match(node,
                            CString::new("jabber:client").expect("CString::new failed").as_ptr(),
                            CString::new("presence").expect("CString::new failed").as_ptr()) == 1
    {
        return 1;
    }
    return 0;
}

#[no_mangle]
extern "C"
fn rexmpp_xml_error (error_type: *const c_char, condition: *const c_char)
                     -> *mut RexmppXML {
    let error : *mut RexmppXML =
        rexmpp_xml_new_elem(CString::new("error")
                            .expect("CString::new failed")
                            .as_ptr(),
                            ptr::null_mut());
    rexmpp_xml_add_attr(error,
                        CString::new("type")
                        .expect("CString::new failed")
                        .as_ptr(),
                        error_type);
    let cond =
        rexmpp_xml_new_elem(condition,
                            CString::new("urn:ietf:params:xml:ns:xmpp-stanzas")
                            .expect("CString::new failed")
                            .as_ptr());
    rexmpp_xml_add_child(error, cond);
    return error;
}

#[no_mangle]
extern "C"
fn rexmpp_xml_find_attr (node_ptr: *mut RexmppXML,
                         name: *const c_char,
                         namespace: *const c_char)
                         -> *mut RexmppXMLAttribute {
    if node_ptr == ptr::null_mut() {
        return ptr::null_mut();
    }
    let node : RexmppXML = unsafe { *node_ptr };
    if node.node_type != NodeType::Element {
        return ptr::null_mut();
    }
    let mut attr_ptr : *mut RexmppXMLAttribute =
        unsafe { node.alt.elem.attributes };
    while attr_ptr != ptr::null_mut() {
        if rexmpp_xml_attr_match(attr_ptr, namespace, name) > 0 {
            return attr_ptr;
        }
        unsafe { attr_ptr = (*attr_ptr).next };
    }
    return ptr::null_mut();
}

#[no_mangle]
extern "C"
fn rexmpp_xml_find_attr_val_ns (node: *mut RexmppXML,
                                name: *const c_char,
                                namespace: *const c_char)
                                -> *const c_char {
    let attr : *mut RexmppXMLAttribute =
        rexmpp_xml_find_attr(node, name, namespace);
    if attr != ptr::null_mut() {
        return unsafe { (*attr).value };
    }
    return ptr::null_mut();
}

#[no_mangle]
extern "C"
fn rexmpp_xml_find_attr_val (node: *mut RexmppXML,
                             name: *const c_char)
                             -> *const c_char {
    rexmpp_xml_find_attr_val_ns(node, name, ptr::null_mut())
}

#[no_mangle]
extern "C"
fn rexmpp_xml_find_child (node_ptr: *mut RexmppXML,
                          namespace: *const c_char,
                          name: *const c_char)
                          -> *mut RexmppXML {
    if node_ptr == ptr::null_mut() {
        return ptr::null_mut();
    }
    let node : RexmppXML = unsafe { *node_ptr };
    if node.node_type != NodeType::Element {
        return ptr::null_mut();
    }
    let mut child: *mut RexmppXML = unsafe { node.alt.elem.children };
    while child != ptr::null_mut() {
        if rexmpp_xml_match(child, namespace, name) > 0 {
            return child;
        }
        unsafe { child = (*child).next };
    }
    return ptr::null_mut();
}


#[no_mangle]
extern "C"
fn rexmpp_xml_eq (n1: *const RexmppXML, n2: *const RexmppXML) -> bool {
    if n1 == n2 {
        return true;
    }
    if n1 == ptr::null_mut() || n1 == ptr::null_mut() {
        return false;
    }
    unsafe {
        match (*n1, *n2) {
            (RexmppXML { node_type : NodeType::Text,
                         alt : RexmppXMLAlt { text: text1 },
                         next: next1 },
             RexmppXML { node_type : NodeType::Text,
                         alt : RexmppXMLAlt { text: text2 },
                         next: next2 }
            ) => strcmp(text1, text2) == 0,
            (RexmppXML
             { node_type : NodeType::Element,
               alt : RexmppXMLAlt
               { elem: RexmppXMLAltElem {
                   qname: RexmppXMLQName {
                       name: name1,
                       namespace: namespace1
                   },
                   attributes: attributes1,
                   children: children1
               } },
               next: _},
             RexmppXML
             { node_type : NodeType::Element,
               alt : RexmppXMLAlt
               { elem: RexmppXMLAltElem {
                   qname: RexmppXMLQName {
                       name: name2,
                       namespace: namespace2
                   },
                   attributes: attributes2,
                   children: children2
               } },
               next: _}
            ) => {
                // Compare names
                if strcmp(name1, name2) != 0
                { return false; }
                // Compare namespaces
                if (namespace1 != namespace2 &&
                    (namespace1 == ptr::null_mut() ||
                     namespace2 == ptr::null_mut() ||
                     strcmp(namespace1, namespace2) != 0))
                { return false; }
                // Compare attributes
                let mut attr1 = attributes1;
                let mut attr2 = attributes2;
                while ! (attr1 == ptr::null_mut() && attr2 == ptr::null_mut()) {
                    if attr1 == ptr::null_mut() {
                        return false;
                    }
                    if attr2 == ptr::null_mut() {
                        return false;
                    }
                    if strcmp((*attr1).qname.name, (*attr2).qname.name) != 0 {
                        return false;
                    }
                    if strcmp((*attr1).value, (*attr2).value) != 0 {
                        return false;
                    }
                    attr1 = (*attr1).next;
                    attr2 = (*attr2).next;
                }
                // Compare children
                let mut child1 = children1;
                let mut child2 = children2;
                while ! (child1 == ptr::null_mut() && child2 == ptr::null_mut())
                {
                    if child1 == ptr::null_mut() {
                        return false;
                    }
                    if child2 == ptr::null_mut() {
                        return false;
                    }
                    if ! rexmpp_xml_eq(child1, child2) {
                        return false;
                    }
                    child1 = (*child1).next;
                    child2 = (*child2).next;
                }
                true
            }
            _ => false
        }
    }
}

#[no_mangle]
extern "C"
fn rexmpp_xml_children (node: *const RexmppXML)
                        -> *mut RexmppXML {
    if node != ptr::null_mut()
        && unsafe { (*node).node_type } == NodeType::Element {
            return unsafe { (*node).alt.elem.children };
        }
    return ptr::null_mut();
}

#[no_mangle]
extern "C"
fn rexmpp_xml_first_elem_child (node: *mut RexmppXML)
                                -> *mut RexmppXML {
    let mut child: *mut RexmppXML = rexmpp_xml_children(node);
    while child != ptr::null_mut() {
        if unsafe { (*child).node_type == NodeType::Element } {
            return child;
        }
        unsafe { child = (*child).next };
    }
    return ptr::null_mut();
}

#[no_mangle]
extern "C"
fn rexmpp_xml_next_elem_sibling (node: *mut RexmppXML)
                                 -> *mut RexmppXML {
    if node == ptr::null_mut() {
        return ptr::null_mut();
    }
    let mut sibling: *mut RexmppXML = unsafe { (*node).next };
    while sibling != ptr::null_mut() {
        if unsafe { (*sibling).node_type == NodeType::Element } {
            return sibling;
        }
        unsafe { sibling = (*sibling).next };
    }
    return ptr::null_mut();
}

#[no_mangle]
extern "C"
fn rexmpp_xml_text (node: *mut RexmppXML)
                    -> *mut c_char {
    if node != ptr::null_mut()
        && unsafe { (*node).node_type == NodeType::Text } {
            return unsafe { (*node).alt.text };
        }
    return ptr::null_mut();
}

#[no_mangle]
extern "C"
fn rexmpp_xml_text_child (node: *mut RexmppXML)
                    -> *mut c_char {
    rexmpp_xml_text(rexmpp_xml_children(node))
}

#[no_mangle]
extern "C"
fn rexmpp_xml_reverse_list (mut node: *mut RexmppXML)
                            -> *mut RexmppXML {
    let mut next;
    let mut prev = ptr::null_mut();
    while node != ptr::null_mut() {
        unsafe {
            next = (*node).next;
            (*node).next = prev;
            prev = node;
            node = next;
        }
    }
    return prev;
}

#[no_mangle]
extern "C"
fn rexmpp_xml_reverse_children (node: *mut RexmppXML)
                                -> *mut RexmppXML {
    unsafe {
        if node == ptr::null_mut() || (*node).node_type != NodeType::Element {
            return node;
        }
        (*node).alt.elem.children =
            rexmpp_xml_reverse_list((*node).alt.elem.children);;

        let mut cur = node;
        while cur != ptr::null_mut() {
            if (*cur).node_type == NodeType::Element &&
                (*cur).alt.elem.children != ptr::null_mut()
            {
                (*cur).alt.elem.children =
                    rexmpp_xml_reverse_children((*cur).alt.elem.children);
            }
            cur = (*cur).next;
        }
    }
    return node;
}
