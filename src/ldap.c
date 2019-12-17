#include <ldap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libguile.h>

// Utility methods for wrapping various calls to free.

void free_values_len(void *values) {
  ldap_value_free_len((struct berval **)values);
}

void free_msg(void *msg) {
  ldap_msgfree((LDAPMessage *)msg);
}

void free_ber(void *ber) {
  ber_free((BerElement *)ber, 0 /* freebuf */);
}

void free_berval(void *berval) {
  ber_bvfree((struct berval*)berval);
}

// As a volatile pointer, the compiler cannot elide this read.
typedef void *(*memset_t)(void *, int, size_t);
static volatile memset_t memset_func = memset;

// Use this function only for strings that have been allocated with a final NULL
void free_secure(void *str) {
  if (str != NULL) {
    memset_func(str, 0, strlen(str));
    free(str);
  }
}

typedef struct ldap_connection {
  LDAP *ld;
  bool bound;
} ldap_connection_t;

static int ldap_version = 3;

static SCM ldap_connection_type;
static SCM key_base_param;
static SCM key_cred_param;
static SCM key_mechanism_param;
static SCM key_name_param;
static SCM key_scope_param;
static SCM key_filter_param;
static SCM key_attrs_param;
static SCM key_attrsonly_param;
static SCM key_serverctrls_param;
static SCM key_clientctrls_param;
static SCM key_timeout_param;
static SCM key_sizelimit_param;


void init_ldap_type (void) {
  SCM name = scm_from_utf8_symbol("ldap_connection");
  SCM slots = scm_list_1(scm_from_utf8_symbol("connection"));
  scm_t_struct_finalize finalizer = NULL;

  ldap_connection_type = scm_make_foreign_object_type(name, slots, finalizer);
}

SCM make_ldap(SCM url_scm) {
  scm_dynwind_begin(0);
  ldap_connection_t *ldap = (ldap_connection_t *) scm_gc_malloc(sizeof(ldap_connection_t), "ldap_connection");
  ldap->ld = NULL;
  ldap->bound = false;
  // Get the string from the url
  char *url_str = scm_to_utf8_stringn(url_scm, NULL);
  scm_dynwind_free(url_str);
  // handle a null url_str
  int err = ldap_initialize(&(ldap->ld), url_str);
  // handle errors
  err = ldap_set_option(ldap->ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);

  scm_dynwind_end();
  return scm_make_foreign_object_1(ldap_connection_type, ldap);
}

int sasl_interaction (LDAP *ld, unsigned int flags, void *defaults,
                      void *sasl_interact) {

}

// Bind methods
static SCM sym_ldap_bind_simple;
static SCM sym_ldap_bind_sasl;

// LDAP SASL interaction
static SCM sym_ldap_sasl_automatic;
static SCM sym_ldap_sasl_interactive;
static SCM sym_ldap_sasl_quiet;

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

SCM unbind_ldap(SCM ldap_obj) {
  scm_assert_foreign_object_type(ldap_connection_type, ldap_obj);

  ldap_connection_t *ldap = scm_foreign_object_ref(ldap_obj, 0);
  if (ldap->bound) {
    ldap_unbind_ext_s(ldap->ld, NULL, NULL);
    ldap->bound = false;
  }

  return SCM_UNSPECIFIED;
}

// Currently synchronous. This is a good candidate for keywords.
SCM search_ldap(SCM ldap_obj, SCM rest) {
  scm_dynwind_begin(0);

  SCM base_scm = SCM_UNDEFINED;
  SCM scope_scm = SCM_UNDEFINED;
  SCM search_scm = SCM_UNDEFINED;
  SCM attrs_scm = SCM_UNDEFINED;
  SCM attrs_only_scm = SCM_UNDEFINED;

  scm_c_bind_keyword_arguments("search-ldap", rest, 0,
                               key_base_param, &base_scm,
                               key_scope_param, &scope_scm,
                               key_filter_param, &search_scm,
                               key_attrs_param, &attrs_scm,
                               key_attrsonly_param, &attrs_only_scm,
                               SCM_UNDEFINED);
  
  scm_assert_foreign_object_type(ldap_connection_type, ldap_obj);
  ldap_connection_t *connection = scm_foreign_object_ref(ldap_obj, 0);

  char *base_str = NULL;
  if (SCM_UNBNDP(base_scm)) {
    // We can define a default base or have this report an error
    scm_wrong_type_arg_msg("search-ldap", 2, base_scm,
                           "a base DN string.");
  } else {
    base_str = scm_to_utf8_stringn(base_scm, NULL /* len */);
    scm_dynwind_free(base_str);
  }

  int scope = LDAP_SCOPE_BASE;
  if (!SCM_UNBNDP(scope_scm)) {
    scope = scm_to_int(scope_scm);
  }

  char *search_str = NULL;
  if (SCM_UNBNDP(search_scm)) {
    scm_wrong_type_arg_msg("search-ldap", 4, search_scm,
                           "a filter string to search for.");
  } else {
    search_str = scm_to_utf8_stringn(search_scm, NULL /* len */);
    scm_dynwind_free(search_str);
  }

  char **attrs = NULL;
  if (!SCM_UNBNDP(attrs_scm)) {
    // Count how many attributes we need, then allocate an array for them -- and
    // include an extra null.
    int attr_count = scm_to_int(scm_length(attrs_scm));
    if (attr_count > 0) {
      size_t attrs_size = (sizeof (char *)) * (attr_count + 1);
      attrs = malloc(attrs_size);
      scm_dynwind_free(attrs);
      memset(attrs, 0, attrs_size);

      char **attr_iter = attrs;
      SCM attr_scm_iter = attrs_scm;
      do {
        SCM attr = scm_car(attr_scm_iter);
        char *attr_str = scm_to_utf8_stringn(attr, NULL /* len */);
        scm_dynwind_free(attr_str);
        *attr_iter = attr_str;

        attr_iter++;
        attr_scm_iter = scm_cdr(attr_scm_iter);
      } while (attr_scm_iter != SCM_EOL);
    }
  }

  int attrs_only = 0;
  if (!SCM_UNBNDP(attrs_only_scm)) {
    attrs_only = scm_is_true(attrs_only_scm);
  }

  LDAPMessage *results = NULL;
  int err = ldap_search_ext_s(connection->ld, base_str, scope, search_str,
                              attrs, attrs_only,
                              NULL /* serverctrls */, NULL /* clientctrls */,
                              NULL /* timeout */, 0 /* sizelimit */, &results);

  if (results != NULL) {
    scm_dynwind_unwind_handler(free_msg, results, SCM_F_WIND_EXPLICITLY);
  }

  // Parse returned us responses, let's navigate that.
  SCM ldap_entries_scm = SCM_EOL;
  LDAPMessage *message = ldap_first_entry(connection->ld, results);
  while (message != NULL) {
    BerElement *ber = NULL;
    SCM entry_scm = SCM_EOL;
    char *attribute_name = ldap_first_attribute(connection->ld, message, &ber);
    scm_dynwind_unwind_handler(free_ber, ber, SCM_F_WIND_EXPLICITLY);
    while (attribute_name != NULL) {
      scm_dynwind_begin(0); // Create a context for this attribute.
      scm_dynwind_unwind_handler(ldap_memfree, attribute_name, SCM_F_WIND_EXPLICITLY);
      SCM attribute_scm = scm_cons(scm_from_utf8_string(attribute_name), SCM_EOL);
      struct berval **values = ldap_get_values_len(connection->ld, message, attribute_name);
      scm_dynwind_unwind_handler(free_values_len, values, SCM_F_WIND_EXPLICITLY);
      int values_count = ldap_count_values_len(values);
      for (int i = 0; i < values_count; i++) {
        attribute_scm =
          scm_append(
            scm_list_2(attribute_scm,
                       scm_cons(scm_from_utf8_stringn(values[i]->bv_val,
                                                      values[i]->bv_len),
                                SCM_EOL)));
      }

      entry_scm =
        scm_append(
          scm_list_2(entry_scm, scm_cons(attribute_scm, SCM_EOL)));

      attribute_name = NULL;
      attribute_name = ldap_next_attribute(connection->ld, message, ber);
      scm_dynwind_end();
    }

    ldap_entries_scm =
      scm_append(scm_list_2(ldap_entries_scm, scm_cons(entry_scm, SCM_EOL)));

    message = ldap_next_entry(connection->ld, message);
  }

  scm_dynwind_end();
  return ldap_entries_scm;
}


void init_keywords() {
  key_base_param = scm_from_utf8_keyword("base");
  key_cred_param = scm_from_utf8_keyword("cred");
  key_mechanism_param = scm_from_utf8_keyword("mechanism");
  key_name_param = scm_from_utf8_keyword("name");
  key_scope_param = scm_from_utf8_keyword("scope");
  key_filter_param = scm_from_utf8_keyword("filter");
  key_attrs_param = scm_from_utf8_keyword("attrs");
  key_attrsonly_param = scm_from_utf8_keyword("attrs-only");
  key_serverctrls_param = scm_from_utf8_keyword("server-ctrls");
  key_clientctrls_param = scm_from_utf8_keyword("client-ctrls");
  key_timeout_param = scm_from_utf8_keyword("timeout");
  key_sizelimit_param = scm_from_utf8_keyword("size-limit");
}

void init_bind_symbols() {
// Bind methods
  sym_ldap_bind_simple = scm_from_utf8_symbol("bind-simple");
  sym_ldap_bind_sasl = scm_from_utf8_symbol("bind-sasl");

// LDAP SASL interaction
  sym_ldap_sasl_automatic = scm_from_utf8_symbol("sasl-automatic");
  sym_ldap_sasl_interactive = scm_from_utf8_symbol("sasl-interactive");
  sym_ldap_sasl_quiet = scm_from_utf8_symbol("sasl-quiet");

}

SCM init_gldap() {
  scm_c_define_gsubr("make-ldap", 1, 0, 0, make_ldap);
  scm_c_define_gsubr("bind-ldap", 2, 0, 1, bind_ldap);
  scm_c_define_gsubr("unbind-ldap", 1, 0, 0, unbind_ldap);
  scm_c_define_gsubr("search-ldap", 1, 0, 1, search_ldap);
  init_keywords();
  init_bind_symbols();
  init_ldap_type();
}

void print_berval(struct berval *val) {
  for (int i = 0; i < val->bv_len; i++) {
    char val_i = val->bv_val[i];
    if (val_i == '\0') {
      break;
    }
    putchar(val_i);
  }
};
