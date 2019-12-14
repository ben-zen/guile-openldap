(load-extension "../libgldap.so" "init_gldap")

(define localhost-ldap (make-ldap "ldap:///"))
(write (search-ldap localhost-ldap
                    #:base "ou=members,dc=example,dc=com"
                    #:scope 1
                    #:filter "(uid=*)")) (newline)
