#include <string.h>
#include "rexmpp_base64.h"

int main () {
  char *original_plain = "test string";
  char *original_base64 = "dGVzdCBzdHJpbmc=";
  char *encoded, *decoded;
  size_t encoded_len, decoded_len;
  if (rexmpp_base64_to(original_plain, strlen(original_plain),
                       &encoded, &encoded_len)) {
    return -1;
  }
  if (rexmpp_base64_from(original_base64, strlen(original_base64),
                         &decoded, &decoded_len)) {
    return -1;
  }
  return strcmp(original_plain, decoded) || strcmp(original_base64, encoded);
}
