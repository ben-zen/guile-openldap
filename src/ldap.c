#include <ldap.h>
#include <stdio.h>
#include <libguile.h>

struct ldap_connection {
  LDAP *ld;
  bool bound;
};

static int ldap_version = 3;

static SCM ldap_connection_type;

void init_ldap_type (void) {
  SCM name = scm_from_utf8_symbol("ldap_connection");
  SCM slots = scm_list_1(scm_from_utf8_symbol("connection"));
  scm_t_struct_finalize finalizer = NULL;

  ldap_connection_type = scm_make_foreign_object_type(name, slots, finalizer);
}

SCM make_ldap(SCM url_scm) {
  struct ldap_connection *ldap = (struct ldap_connection *) scm_gc_malloc(sizeof(struct ldap_connection), "ldap_connection");
  ldap->ld = NULL;
  ldap->bound = false;
  // Get the string from the url
  char *url_str = scm_to_utf8_stringn(url_scm, NULL);
  // handle a null url_str
  int err = ldap_initialize(&(ldap->ld), url_str);
  bound = true;
  // handle errors
  err = ldap_set_option(ldap->ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
  
  free(url_str);
  return scm_make_foreign_object_1(ldap_connection_type, ldap);
}

SCM unbind_ldap(SCM ldap_obj) {
  scm_assert_foreign_object_type(ldap_connection_type, ldap_obj);

  struct ldap_connection *ldap = scm_foreign_object_ref(ldap_obj, 0);
  if (ldap->bound) {
    ldap_unbind(ldap->ld);
    ldap->bound = false;
  }

  return SCM_UNSPECIFIED;
}

// Currently synchronous.
SCM search_ldap(SCM ldap_obj, SCM bind_scm, SCM scope, SCM search_scm, SCM attrs_scm) {
  scm_assert_foreign_object_type(ldap_connection_type, ldap_obj);
  
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

int main (int argc, char** argv) {
  char *ldap_url = (argc > 1) ? argv[1] : "ldap://127.0.0.1:389/";
  LDAP* ldap = NULL;
  int err = ldap_initialize(&ldap, ldap_url);
  err = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
  if (err != LDAP_OPT_SUCCESS) {
    return err;
  }

  /* search? */
  LDAPMessage *results = NULL;
  err = ldap_search_ext_s(ldap, "ou=members,dc=example,dc=com",
                          LDAP_SCOPE_ONELEVEL, "(uid=geoff)", NULL /* attrs[] */,
                          0 /* attrsonly */, NULL /* serverctrls */, NULL
                          /* clientctrls */, NULL /* timeout */, 0 /* sizelimit */, &results);

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
