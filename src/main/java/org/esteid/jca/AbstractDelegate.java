package org.esteid.jca;

import apdu4j.HexUtils;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.Console;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public abstract class AbstractDelegate {
    public static final TrustManager DUMMY = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };
    protected static final Map<String, byte[]> digestInfos;
    protected static final Map<String, String> hashAlgos;

    static {
        Map<String, byte[]> tmp1 = new HashMap<>();
        tmp1.put("SHA256withRSA", HexUtils.hex2bin("3031300d060960864801650304020105000420"));
        tmp1.put("SHA384withRSA", HexUtils.hex2bin("3041300d060960864801650304020205000430"));
        tmp1.put("SHA512withRSA", HexUtils.hex2bin("3051300d060960864801650304020305000440"));
        digestInfos = Collections.unmodifiableMap(tmp1);

        Map<String, String> tmp2 = new HashMap<>();
        tmp2.put("SHA256withRSA", "SHA-256");
        tmp2.put("SHA384withRSA", "SHA-384");
        tmp2.put("SHA512withRSA", "SHA-512");
        hashAlgos = Collections.unmodifiableMap(tmp2);
    }

    protected X509Certificate cert = null;

    public abstract String getName();

    public abstract X509Certificate readCertificate() throws CertificateException;

    public X509Certificate getCertificate() throws CertificateException {
        if (cert == null)
            cert = readCertificate();
        return cert;
    }


    public abstract byte[] getSignature(byte[] dtbs, String algorithm) throws SignatureException;


    public static final NotificationInterface CONSOLE = new NotificationInterface() {
        @Override
        public void showControlCode(String code) {
            System.out.println("Control code: " + code);
        }

        @Override
        public String askPinCode(String info) {
            Console c = System.console();
            if (c != null) {
                char[] p = c.readPassword(info);
                if (p == null)
                    throw new IllegalStateException("Please enter a PIN code");
                return new String(p);
            } else {
                throw new RuntimeException("Need access to console for asking PIN!");
            }
        }
    };
}
