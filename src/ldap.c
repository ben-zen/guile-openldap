#include <ldap.h>
#include <stdio.h>
//#include <libguile.h>

/* mark */

/* free */

/* print */

/* equalp */

void print_berval(struct berval *val) {
  for (int i = 0; i < val->bv_len; i++) {
    char val_i = val->bv_val[i];
    if (val_i == '\0') {
      break;
    }
    putchar(val_i);
  }
};

static int ldap_version = 3;

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
