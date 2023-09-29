#include <string.h>
#include <stdlib.h>
#include "rexmpp_xml.h"

int main () {
  int ret = 0;

  rexmpp_xml_attr_t
    foo_attributes = { .qname = {"bar", NULL},
                       .value = "baz",
                       .next = NULL },
    quux_attributes_g = { .qname = {"g", NULL},
                          .value = "h",
                          .next = NULL },
    quux_attributes =
    { .qname = {"e", NULL},
      .value = "f",
      .next = &quux_attributes_g };
  rexmpp_xml_t
    quux = { .type = REXMPP_XML_ELEMENT,
      .alt.elem =
      { .qname = {"quux", NULL},
        .attributes = &quux_attributes,
        .children = NULL
      },
      .next = NULL
    },
    qux_text = { .type = REXMPP_XML_TEXT,
                 .alt.text = "a b c d",
                 .next = NULL },
    qux = { .type = REXMPP_XML_ELEMENT,
      .alt.elem =
      { .qname = {"qux", "urn:dummy"},
        .attributes = NULL,
        .children = &qux_text
      },
      .next = &quux
    },
    xml =
    { .type = REXMPP_XML_ELEMENT,
      .alt.elem =
      { .qname = {"foo", NULL},
        .attributes = &foo_attributes,
        .children = &qux
      },
      .next = NULL
    };

  char *str_new = rexmpp_xml_serialize (&xml, 0);
  if (str_new == NULL) {
    ret = -1;
  } else {
    rexmpp_xml_t *xml_new = rexmpp_xml_parse (str_new, strlen(str_new));
    if (xml_new == NULL) {
      ret = -2;
    } else {
      /* Compare the XML structures. */
      ret = (rexmpp_xml_eq(&xml, xml_new) == 0);
      rexmpp_xml_free(xml_new);
    }
    free(str_new);
  }
  return ret;
}
