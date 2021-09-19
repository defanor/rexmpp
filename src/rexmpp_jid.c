/**
   @file rexmpp_jid.c
   @brief JID parsing and manipulation
   @author defanor <defanor@uberspace.net>
   @date 2020
   @copyright MIT license.
*/

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#ifdef HAVE_ICU
#include <unicode/ustring.h>
#include <unicode/uset.h>
#include <unicode/uspoof.h>
#endif
#include "rexmpp_jid.h"

int rexmpp_jid_parse (const char *str, struct rexmpp_jid *jid) {
  const char *resource = NULL, *domain = str;
  size_t i;
  size_t resource_len = 0, local_len = 0;
  size_t domain_len, bare_len, full_len = strlen(str);
  domain_len = full_len;
  bare_len = full_len;

  /* Find the separators. */
  for (i = 0; i < full_len; i++) {
    if (local_len == 0 && str[i] == '@') {
      if (i == 0) {
        /* '@' is in the very beginning, an error. */
        return -1;
      }
      local_len = i;
      domain_len -= local_len + 1;
      domain = str + i + 1;
    }
    if (str[i] == '/') {
      if (i == full_len - 1) {
        /* '/' is in the end, that's an error. */
        return -1;
      }
      resource_len = full_len - i - 1;
      domain_len -= resource_len + 1;
      bare_len -= resource_len + 1;
      resource = str + i + 1;
      break;
    }
  }

  /* Check all the lengths. */
  if (full_len > 3071 || bare_len > 2047 ||
      local_len > 1023 || resource_len > 1023 ||
      domain_len > 1023 || domain_len < 1) {
    return -1;
  }

  /* Copy all the parts. */
  strncpy(jid->full, str, full_len);
  jid->full[full_len] = '\0';
  strncpy(jid->bare, str, bare_len);
  jid->bare[bare_len] = '\0';
  strncpy(jid->local, str, local_len);
  jid->local[local_len] = '\0';
  strncpy(jid->domain, domain, domain_len);
  jid->domain[domain_len] = '\0';
  strncpy(jid->resource, resource, resource_len);
  jid->resource[resource_len] = '\0';

  return 0;
}

/* <https://tools.ietf.org/html/rfc7622#section-3>,
   <https://tools.ietf.org/html/rfc8265#section-3.3> */
int rexmpp_jid_check (struct rexmpp_jid *jid) {
#ifdef HAVE_ICU
  UErrorCode err = U_ZERO_ERROR;
  UChar local[1023], domain[1023], resource[1023];
  int32_t local_len = 0, domain_len = 0, resource_len = 0;

  /* Initial length checks are performed on parsing. */

  /* Ensure that it's all valid UTF-8. */

  u_strFromUTF8(local, 1023, &local_len, jid->local, -1, &err);
  if (U_FAILURE(err)) {
    return 0;
  }
  /* TODO: IDNA2008 on domain part. */
  u_strFromUTF8(domain, 1023, &domain_len, jid->domain, -1, &err);
  if (U_FAILURE(err)) {
    return 0;
  }
  u_strFromUTF8(resource, 1023, &resource_len, jid->resource, -1, &err);
  if (U_FAILURE(err)) {
    return 0;
  }

  /* TODO: width mapping. */


  /* Check character classes */
  USpoofChecker *sc;
  int32_t spoof;

  /* IdentifierClass: {Ll, Lu, Lo, Nd, Lm, Mn, Mc} + 0x21 to 0x7e */
  USet *identifier_chars = uset_openEmpty();
  uset_applyIntPropertyValue(identifier_chars, UCHAR_GENERAL_CATEGORY_MASK,
                             U_GC_LL_MASK | U_GC_LU_MASK | U_GC_LO_MASK |
                             U_GC_ND_MASK | U_GC_LM_MASK | U_GC_MN_MASK |
                             U_GC_MC_MASK,
                             &err);
  if (U_FAILURE(err)) {
    return 0;
  }
  uset_addRange(identifier_chars, 0x21, 0x7e);

  sc = uspoof_open(&err);
  if (U_FAILURE(err)) {
    uset_close(identifier_chars);
    return 0;
  }
  uspoof_setChecks(sc, USPOOF_CHAR_LIMIT, &err);
  if (U_FAILURE(err)) {
    uset_close(identifier_chars);
    uspoof_close(sc);
    return 0;
  }
  uspoof_setAllowedChars(sc, identifier_chars, &err);
  if (U_FAILURE(err)) {
    uset_close(identifier_chars);
    uspoof_close(sc);
    return 0;
  }
  spoof = uspoof_check(sc, local, local_len, NULL, &err);
  if (U_FAILURE(err) || spoof) {
    uset_close(identifier_chars);
    uspoof_close(sc);
    return 0;
  }

  /* FreeformClass: Zs, {Sm, Sc, Sk, So}, {Pc, Pd, Ps, Pe, Pi, Pf,
     Po}, toNFKC(cp) != cp ones, {Lt, Nl, No, Me}, and IdentifierClass
     ones. */

  /* TODO: https://tools.ietf.org/html/rfc8264#section-9.17 */
  USet *freeform_chars = uset_openEmpty();
  uset_applyIntPropertyValue(freeform_chars, UCHAR_GENERAL_CATEGORY_MASK,
                             U_GC_ZS_MASK | U_GC_SM_MASK | U_GC_SC_MASK |
                             U_GC_SK_MASK | U_GC_SO_MASK | U_GC_PC_MASK |
                             U_GC_PD_MASK | U_GC_PS_MASK | U_GC_PE_MASK |
                             U_GC_PI_MASK | U_GC_PF_MASK | U_GC_PO_MASK |
                             U_GC_LT_MASK | U_GC_NL_MASK | U_GC_NO_MASK |
                             U_GC_ME_MASK,
                             &err);
  if (U_FAILURE(err)) {
    uset_close(freeform_chars);
    uset_close(identifier_chars);
    uspoof_close(sc);
    return 0;
  }
  uset_addAll(freeform_chars, identifier_chars);
  uset_close(identifier_chars);

  spoof = uspoof_check(sc, resource, resource_len, NULL, &err);
  if (U_FAILURE(err) || spoof) {
    uset_close(freeform_chars);
    uspoof_close(sc);
    return 0;
  }
  uset_close(freeform_chars);
  uspoof_close(sc);

  /* TODO: case mapping, u_strToLower */

  /* TODO: normalization, unorm2_normalize */

  /* TODO: directionality */
#else
  (void)jid;
#endif
  return 1;
}
