#include <string.h>
#include <stdlib.h>
#include "rexmpp_xml.h"

int main () {
  int ret = 0;

  char *str = "<foo bar=\"baz\">"
    "<qux xmlns=\"urn:test\">a b c d</qux>"
    "<quux e=\"f\" g=\"h\"/>"
    "</foo>";
  rexmpp_xml_t *xml = rexmpp_xml_parse (str, strlen(str));

  if (xml == NULL) {
    ret = -1;
  } else {
    char *str_new = rexmpp_xml_serialize (xml, 0);
    if (str_new == NULL) {
      ret = -2;
    } else {
      ret = strcmp(str, str_new);
      free(str_new);
    }
    rexmpp_xml_free(xml);
  }
  return ret;
}
