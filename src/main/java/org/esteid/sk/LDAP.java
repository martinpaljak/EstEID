/**
 * Copyright (c) 2014-2017 Martin Paljak
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.esteid.sk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

public final class LDAP {
    private static final Logger logger = LoggerFactory.getLogger(LDAP.class);
    private volatile static String server = "ldap://ldap.sk.ee:389";

    // Given idcode, return a map of  certificates
    @SuppressWarnings("sunapi")
    public static Map<String, X509Certificate> query(String idcode) throws NamingException, CertificateException {
        logger.trace("Querying LDAP for " + idcode);
        Map<String, X509Certificate> result = new HashMap<>();
        LdapContext ctx = null;
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, com.sun.jndi.ldap.LdapCtxFactory.class.getCanonicalName());
            env.put(Context.PROVIDER_URL, server);

            ctx = new InitialLdapContext(env, null);

            SearchControls scope = new SearchControls();
            scope.setSearchScope(SearchControls.SUBTREE_SCOPE);
            // Search
            NamingEnumeration<SearchResult> results = ctx.search("'c=EE'", "(serialNumber=" + idcode + ")", scope);
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            while (results.hasMoreElements()) {
                SearchResult r = results.nextElement();
                logger.trace("{} has {}", idcode, r.getName());
                // Get certificate
                Attribute crt = r.getAttributes().get("userCertificate;binary");
                if (crt == null) {
                    throw new NamingException("Result does not contain a certificate!?");
                }
                byte[] cert = (byte[]) crt.get();
                result.put(r.getName(), (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cert)));
            }
        } finally {
            if (ctx != null)
                ctx.close();
        }
        logger.trace("Returning " + result.size() + " certificates for " + idcode);
        return result;
    }

    public static Set<X509Certificate> fetch(String idcode) throws CertificateException, NamingException {
        Set<X509Certificate> result = new HashSet<>();
        result.addAll(query(idcode).values());
        return result;
    }
}
