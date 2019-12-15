(load-extension "../libgldap.so" "init_gldap")

(define localhost-ldap (make-ldap "ldap:///"))

(display "Binding to a user with simple auth:") (newline)
(write (bind-ldap localhost-ldap
                  'bind-simple
                  #:name "cn=geoff,ou=members,dc=example,dc=com"
                  #:cred "hacker")) (newline)

(write (bind-ldap localhost-ldap
                  'bind-simple
                  #:name "cn=sasha,ou=members,dc=example,dc=com"
                  #:cred "cracker")) (newline)
