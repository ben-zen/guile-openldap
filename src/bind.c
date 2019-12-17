// Copyright (C) 2019 Ben Lewis <zenrider@blacklodgeresearch.org>
// Licensed as described in the LICENSE file.

#include <ldap.h>
#include <libguile.h>
#include <sasl.h>
#include <stdbool.h>
#include <stdio.h>

#include "symbols.h"

int sasl_interaction (LDAP *ld, unsigned int flags, void *defaults,
                      void *sasl_interact) {

}

SCM bind_ldap(SCM ld_scm, SCM bind_method, SCM rest) {
  scm_dynwind_begin(0);
  scm_assert_foreign_object_type(ldap_connection_type, ld_scm);
  ldap_connection_t *ldap = scm_foreign_object_ref(ld_scm, 0);

  if (ldap->bound) {
    // error! This should only be run once.
  }

  SCM bind_result = SCM_UNDEFINED;

  SCM name_scm = SCM_UNDEFINED; // DN, not used in SASL
  SCM cred_scm = SCM_UNDEFINED;
  SCM mechanism_scm = SCM_UNDEFINED;
  
  scm_c_bind_keyword_arguments("bind-ldap", rest, 0,
                               key_name_param, &name_scm,
                               key_cred_param, &cred_scm,
                               key_mechanism_param, &mechanism_scm,
                               SCM_UNDEFINED);

  // We'll parse parameters based on bind method, since each method uses these
  // options differently.
  
  char *mechanism = NULL;
  if (bind_method == sym_ldap_bind_simple) {
    // null is the same as simple here.
  } else if (bind_method == sym_ldap_bind_sasl) {
    // Get the mechanism
    if (SCM_UNBNDP(mechanism_scm)) {
      // Error!
    }

    mechanism = scm_to_utf8_stringn(mechanism_scm, NULL /* len */);
    scm_dynwind_free(mechanism);
  } else {
    // Error!
  }
  
  // Expect name and cred to be populated
  char *name = NULL;
  if (SCM_UNBNDP(name_scm)) {
    // Error!
  } else {
    name = scm_to_utf8_stringn(name_scm, NULL /* len */);
    scm_dynwind_free(name);
  }

  if (SCM_UNBNDP(cred_scm)) {
    // Error!
  }
  
  char *cred = scm_to_utf8_stringn(cred_scm, NULL /* len */);
  struct berval cred_bv;
  ber_str2bv(cred, strlen(cred), 0, &cred_bv);
  // Securely erase this buffer! I'd also like to scrub the SCM somehow.
  scm_dynwind_unwind_handler(free_secure, cred, SCM_F_WIND_EXPLICITLY);
  // scm_dynwind_unwind_handler(free_berval, cred_bv, SCM_F_WIND_EXPLICITLY);

  struct berval *server_cred = NULL;
  int result = ldap_sasl_bind_s(ldap->ld, name, mechanism, &cred_bv,
                                NULL /* sctrls */, NULL /* cctrls */,
                                &server_cred);
  scm_dynwind_unwind_handler(free_berval, server_cred, SCM_F_WIND_EXPLICITLY);
  if (result == 0) {
    ldap->bound = true;
    bind_result = SCM_BOOL_T;
    if (server_cred != NULL) {
      bind_result = scm_from_utf8_stringn(server_cred->bv_val,
                                          server_cred->bv_len);
    }
  } else {
    printf("ldap_sasl_bind_s returned %d\n", result);
    // build an error result that captures the result _and_ the string for it.
  }

  scm_dynwind_end();
  return bind_result;
}
