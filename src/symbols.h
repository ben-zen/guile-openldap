// Copyright (C) 2019 Ben Lewis <zenrider@blacklodgeresearch.org>
// Licensed as described in the LICENSE file.

#ifndef _SYMBOLS_H_
#define _SYMBOLS_H_
// Parameters
extern SCM key_base_param;
extern SCM key_cred_param;
extern SCM key_mechanism_param;
extern SCM key_name_param;
extern SCM key_scope_param;
extern SCM key_filter_param;
extern SCM key_attrs_param;
extern SCM key_attrsonly_param;
extern SCM key_serverctrls_param;
extern SCM key_clientctrls_param;
extern SCM key_timeout_param;
extern SCM key_sizelimit_param;

// Bind methods
extern SCM sym_ldap_bind_simple;
extern SCM sym_ldap_bind_sasl;

// LDAP SASL interaction
extern SCM sym_ldap_sasl_automatic;
extern SCM sym_ldap_sasl_interactive;
extern SCM sym_ldap_sasl_quiet;

#endif // _SYMBOLS_H_
