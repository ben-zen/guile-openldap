ldaptest : src/ldap.c
	cc -L/usr/lib/x86_64-linux-gnu -oldaptest src/ldap.c -lldap -llber

gldap.so : src/ldap.c
	cc -ggdb -c -I/usr/include/guile/2.2 -fpic -o gldap.o src/ldap.c
	cc -ggdb -L/usr/lib/x86_64-linux-gnu -shared -o libgldap.so gldap.o -lldap -llber
