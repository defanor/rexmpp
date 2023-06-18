extern crate libc;
use libc::{strdup, free};
use std::os::raw::{c_char, c_int, c_void, c_uint};
use std::ptr;
use std::ffi::{CStr, CString};
use std::clone::Clone;

// extern {
//     fn rexmpp_xml_serialize (node: *mut RexmppXML) -> *mut c_char;
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
        while old_attr_ptr != ptr::null_mut() {
            let old_attr = unsafe { *old_attr_ptr };
            let new_attr_ptr = rexmpp_xml_attr_new(old_attr.qname.name,
                                                   old_attr.qname.namespace,
                                                   old_attr.value);
            unsafe { (*next_attr_ptr_ptr) = new_attr_ptr };
            next_attr_ptr_ptr = unsafe { &mut ((*new_attr_ptr).next) };
            old_attr_ptr = old_attr.next;
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
fn rexmpp_xml_qname_free (qname_ptr: *const RexmppXMLQName) {
    if qname_ptr == ptr::null_mut() {
        return;
    }
    let mut qname : RexmppXMLQName = unsafe { *qname_ptr };
    if qname.name != ptr::null_mut() {
        unsafe { free(qname.name as *mut c_void) };
        qname.name = ptr::null_mut();
    }
    if qname.namespace != ptr::null_mut() {
        unsafe { free(qname.namespace as *mut c_void) };
        qname.namespace = ptr::null_mut();
    }
}

#[no_mangle]
extern "C"
fn rexmpp_xml_attribute_free (attr_ptr: *mut RexmppXMLAttribute) {
    if attr_ptr == ptr::null_mut() {
        return;
    }
    let mut attr : RexmppXMLAttribute = unsafe { *Box::from_raw(attr_ptr) };
    rexmpp_xml_qname_free(&(attr.qname));
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
                        alt : RexmppXMLAlt { elem: element },
                        next: _} => {
                rexmpp_xml_qname_free(&(element.qname));
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
fn rexmpp_xml_children (node: *mut RexmppXML)
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
