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

typedef struct ldap_connection {
  LDAP *ld;
  bool bound;
} ldap_connection_t;

static int ldap_version = 3;

static SCM ldap_connection_type;
static SCM key_base_param;
static SCM key_bind_param;
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
  ldap->bound = true;
  // handle errors
  err = ldap_set_option(ldap->ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);

  scm_dynwind_end();
  return scm_make_foreign_object_1(ldap_connection_type, ldap);
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

  scm_c_bind_keyword_arguments("search-ldap", rest, 0,
                               key_base_param, &base_scm,
                               key_scope_param, &scope_scm,
                               key_filter_param, &search_scm,
                               key_attrs_param, &attrs_scm,
                               SCM_UNDEFINED);
  
  scm_assert_foreign_object_type(ldap_connection_type, ldap_obj);
  ldap_connection_t *connection = scm_foreign_object_ref(ldap_obj, 0);

  char *base_str = NULL;
  if (SCM_UNBNDP(base_scm)) {
    // We can define a default base or have this report an error
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
  } else {
    search_str = scm_to_utf8_stringn(search_scm, NULL /* len */);
    scm_dynwind_free(search_str);
  }
  
  LDAPMessage *results = NULL;
  int err = ldap_search_ext_s(connection->ld, base_str, scope, search_str,
                              NULL /* attrs[] */, 0 /* attrsonly */,
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
  key_bind_param = scm_from_utf8_keyword("bind");
  key_scope_param = scm_from_utf8_keyword("scope");
  key_filter_param = scm_from_utf8_keyword("filter");
  key_attrs_param = scm_from_utf8_keyword("attrs");
  key_attrsonly_param = scm_from_utf8_keyword("attrs-only");
  key_serverctrls_param = scm_from_utf8_keyword("server-ctrls");
  key_clientctrls_param = scm_from_utf8_keyword("client-ctrls");
  key_timeout_param = scm_from_utf8_keyword("timeout");
  key_sizelimit_param = scm_from_utf8_keyword("size-limit");
  
}

SCM init_gldap() {
  scm_c_define_gsubr("make-ldap", 1, 0, 0, make_ldap);
  scm_c_define_gsubr("unbind-ldap", 1, 0, 0, unbind_ldap);
  scm_c_define_gsubr("search-ldap", 1, 0, 1, search_ldap);
  init_keywords();
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

/*
int main (int argc, char** argv) {
  char *ldap_url = (argc > 1) ? argv[1] : "ldap://127.0.0.1:389/";
  LDAP* ldap = NULL;
  int err = ldap_initialize(&ldap, ldap_url);
  err = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
  if (err != LDAP_OPT_SUCCESS) {
    return err;
  }

  // search?
  LDAPMessage *results = NULL;
  err = ldap_search_ext_s(ldap, "ou=members,dc=example,dc=com",
                          LDAP_SCOPE_ONELEVEL, "(uid=geoff)", NULL , //attrs[]
                          0, // attrsonly
                          NULL, // serverctrls
                          NULL, 
                          /* clientctrls, NULL /* timeout, 0 /* sizelimit, &results);

  int count = ldap_count_messages(ldap, results);
  printf("Received %i %s.\n", count, (count == 1) ? "result" : "results");

  if (count == 0) {
    return 0;
  }

  LDAPMessage *message = ldap_first_entry(ldap, results);

  while (message != NULL) {
    BerElement *ber = NULL;
    char *attribute_name = ldap_first_attribute(ldap, message, &ber);
    while (attribute_name != NULL) {
      printf("Writing attribute: %s\n", attribute_name);
      struct berval **values = ldap_get_values_len(ldap, message, attribute_name);
      int values_count = ldap_count_values_len(values);
      for (int i = 0; i < values_count; i++) {
        puts("Attribute value: ");
        print_berval(values[i]);
        putchar('\n');
      }

      ldap_value_free_len(values);
      ldap_memfree(attribute_name);
      attribute_name = NULL;
      attribute_name = ldap_next_attribute(ldap, message, ber);
    }

    ber_free(ber, 0);
    message = ldap_next_entry(ldap, message);
  }
  
  
  ldap_msgfree(results);
  return 0;
}
*/
