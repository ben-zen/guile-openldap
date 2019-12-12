(load-extension "../libgldap.so" "init_gldap")

(define localhost-ldap (make-ldap "ldap:///"))
(write (search-ldap localhost-ldap "ou=members,dc=example,dc=com" 1 "(uid=*)" '())) (newline)
