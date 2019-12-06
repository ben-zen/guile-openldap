#include <ldap.h>
#include <stdio.h>
//#include <libguile.h>

/* mark */

/* free */

/* print */

/* equalp */

static int ldap_version = 3;

int main (int argc, char** argv) {
  char *ldap_url = (argc > 1) ? argv[1] : "ldap://127.0.0.1:389/";
  LDAP* ldap_info = NULL;
  int err = ldap_initialize(&ldap_info, ldap_url);
  err = ldap_set_option(ldap_info, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
  if (err != LDAP_OPT_SUCCESS) {
    return err;
  }

  /* search? */
  LDAPMessage *results = NULL;
  err = ldap_search_ext_s(ldap_info, "ou=members,dc=example,dc=com",
                          LDAP_SCOPE_ONELEVEL, "(uid=geoff)", NULL /* attrs[] */,
                          0 /* attrsonly */, NULL /* serverctrls */, NULL
                          /* clientctrls */, NULL /* timeout */, 0 /* sizelimit */, &results);

  int count = ldap_count_messages(ldap_info, results);
  printf("Received %i %s.\n", count, (count == 1) ? "result" : "results");
  
  
  ldap_msgfree(results);
  return 0;
}
