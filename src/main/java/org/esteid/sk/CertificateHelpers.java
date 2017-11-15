/**
 * Copyright (c) 2017 Martin Paljak
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

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;

public final class CertificateHelpers {

    public static String crt2pem(X509Certificate c) throws IOException {
        try {
            return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(c.getEncoded()) + "\n-----END CERTIFICATE-----";
        } catch (CertificateEncodingException e) {
            throw new IOException(e);
        }
    }

    public static Collection<X509Certificate> filter_card_auth_certs(Collection<X509Certificate> i) {
        List<X509Certificate> result = new ArrayList<>();
        for (X509Certificate c : i) {
            String s = c.getSubjectX500Principal().toString();
            if (s.contains("digital signature"))
                continue;
            if (s.contains("ESTEID (MOBIIL-ID)"))
                continue;
            result.add(c);
        }
        return result;
    }

    public static Collection<X509Certificate> filter_by_algorithm(Collection<X509Certificate> i, String algo) {
        List<X509Certificate> result = new ArrayList<>();
        for (X509Certificate c : i) {
            if (c.getPublicKey().getAlgorithm().equals(algo))
                result.add(c);
        }
        return result;
    }
}
