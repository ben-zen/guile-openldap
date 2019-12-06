ldaptest : src/ldap.c
	cc -L/usr/lib/x86_64-linux-gnu -oldaptest src/ldap.c -lldap
