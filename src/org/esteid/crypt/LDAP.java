package org.esteid.crypt;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import apdu4j.HexUtils;

public class LDAP {

	// Given idcode, return a map of  certificates
	public static Map<String, X509Certificate> get_certs(String idcode) throws NamingException, GeneralSecurityException {
		Hashtable<String, String> env = new Hashtable<>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, "ldap://ldap.sk.ee:389");
		LdapContext ctx = new InitialLdapContext(env, null);

		SearchControls scope = new SearchControls();
		scope.setSearchScope(SearchControls.SUBTREE_SCOPE);
		// Search
		NamingEnumeration<SearchResult> results = ctx.search("'c=EE'", "(serialNumber=" + idcode +")", scope);
		Map<String, X509Certificate> certs = new HashMap<>();
		CertificateFactory factory = CertificateFactory.getInstance("X509");
		while (results.hasMoreElements()) {
			SearchResult result = results.nextElement();
			String name = result.getName();
			// Get certificate
			Attribute crt = result.getAttributes().get("userCertificate;binary");
			if (crt == null) {
				throw new IllegalArgumentException("Result does not contain certificate!");
			}
			byte [] cert = (byte [])crt.get();
			certs.put(name, (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(cert)));
		}
		return certs;
	}

	// Extract meaningful values from subject to a handy map
	public static Map<String, String> cert2subjectmap(X509Certificate c) throws InvalidNameException {
		Map<String, String> m = new HashMap<>();
		LdapName ldapDN = new LdapName(c.getSubjectX500Principal().getName());
		for(Rdn rdn: ldapDN.getRdns()) {
			if (rdn.getValue() instanceof byte[]) {
				m.put(rdn.getType(), HexUtils.bin2hex((byte[]) rdn.getValue()));
			} else if (rdn.getValue() instanceof String) {
				m.put(rdn.getType(), (String) rdn.getValue());
			}
		}
		return m;
	}
	public static void main(String[] args) throws Exception {
		Map<String, X509Certificate> certs = get_certs("38207162722");
		for(Map.Entry<String, X509Certificate> entry: certs.entrySet()) {
			System.out.println(entry.getKey() + " = " + entry.getValue().getSubjectX500Principal());
		}
	}
}
