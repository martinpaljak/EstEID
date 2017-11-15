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
package org.esteid.jca;

import javax.net.ssl.X509ExtendedKeyManager;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public final class DelegatingProvider extends Provider {
    private static final String ALIAS = "DelegatedAlias";

    private final AbstractDelegate delegate;
    private X509Certificate cert;

    protected DelegatingProvider(AbstractDelegate delegate) {
        super("DelegatedKey", 0.1d, "Indirect access to a certificate and key");
        this.delegate = delegate;

        putService(new DelegatedSignatureService(this, "NONEwithRSA"));

        putService(new DelegatedSignatureService(this, "SHA256withRSA"));
        putService(new DelegatedSignatureService(this, "SHA384withRSA"));
        putService(new DelegatedSignatureService(this, "SHA512withRSA"));
    }

    public static DelegatingProvider fromDelegate(AbstractDelegate delegate) {
        return new DelegatingProvider(delegate);
    }

    public X509ExtendedKeyManager getKeyManager() {
        try {
            if (cert == null) {
                cert = delegate.getCertificate();
            }
        } catch (CertificateException e) {
            throw new RuntimeException("Could not read certificate", e);
        }

        return new X509ExtendedKeyManager() {
            @Override
            public String[] getClientAliases(String s, Principal[] principals) {
                //System.out.println("getClientAliases");
                if (cert.getPublicKey().getAlgorithm().equals(s))
                    return new String[]{ALIAS};
                return new String[0];
            }

            @Override
            public String chooseClientAlias(String[] strings, Principal[] principals, Socket socket) {
                //System.out.println("chooseClientAlias");
                for (String k : strings) {
                    if (cert.getPublicKey().getAlgorithm().equals(k)) {
                        System.out.println("Algorithm " + k + " is usable with " + ALIAS);
                        return ALIAS;
                    }
                }
                // We only have one
                return null;
            }

            @Override
            public String[] getServerAliases(String s, Principal[] principals) {
                return new String[0];
            }

            @Override
            public String chooseServerAlias(String s, Principal[] principals, Socket socket) {
                return null;
            }

            @Override
            public X509Certificate[] getCertificateChain(String s) {
                //System.out.println("Getting certificate chain for " + s);
                if (s.equals(ALIAS)) {
                    return new X509Certificate[]{cert};
                } else {
                    return new X509Certificate[0];
                }
            }

            @Override
            public PrivateKey getPrivateKey(String s) {
                //System.out.println("Getting key for " + s);
                if (s.equals(ALIAS)) {
                    return new DelegatedKey(cert.getPublicKey().getAlgorithm());
                } else {
                    return null;
                }
            }
        };
    }

    static final class DelegatedSignatureService extends Service {
        private AbstractDelegate delegate;

        public DelegatedSignatureService(DelegatingProvider provider, String algorithm) {
            super(provider, "Signature", algorithm, DelegatedSignature.class.getName(), null, null);
            //System.out.println("Creating service for " + algorithm);
            this.delegate = provider.delegate;
        }

        @Override
        public boolean supportsParameter(Object parameter) {
            if (parameter instanceof DelegatedKey) {
                return true;
            }
            return false;
        }

        @Override
        public Object newInstance(Object constructorParameter) throws NoSuchAlgorithmException {
            return new DelegatedSignature(getAlgorithm(), delegate);
        }
    }

    public static final class DelegatedSignature extends SignatureSpi {
        private final String algorithm;
        private final AbstractDelegate delegate;
        private final ByteArrayOutputStream dtbs_baos = new ByteArrayOutputStream();

        DelegatedSignature(String hash, AbstractDelegate delegate) {
            this.delegate = delegate;
            this.algorithm = hash;
        }

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            throw new InvalidKeyException("DelegatedSignature does not support verification");
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            if (!(privateKey instanceof DelegatedKey))
                throw new InvalidKeyException("Unknown key " + privateKey.getClass());
        }

        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            dtbs_baos.write(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
            dtbs_baos.write(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            byte[] dtbs = dtbs_baos.toByteArray();
            return delegate.getSignature(dtbs, algorithm);
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            throw new SignatureException("DelegatedSignature does not support verification");
        }

        @Override
        @SuppressWarnings("deprecation")
        protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        }

        @Override
        @SuppressWarnings("deprecation")
        protected Object engineGetParameter(String param) throws InvalidParameterException {
            return null;
        }
    }

    public static final class DelegatedKey implements Key, PrivateKey {
        private final String algorithm;

        DelegatedKey(String algorithm) {
            this.algorithm = algorithm;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return "DelegatedKey";
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }

    // XXX: Just to silence findbugs
    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }
    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
