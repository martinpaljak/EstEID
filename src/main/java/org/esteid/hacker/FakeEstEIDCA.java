/**
 * Copyright (C) 2014-2017 Martin Paljak
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package org.esteid.hacker;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

// Look-alikes for sk.ee root, intermediate and end-user certificates.
public class FakeEstEIDCA {

    // KeyStore constants
    private static final char[] password = "infected".toCharArray();
    private static final String root = "root";
    private static final String esteid = "esteid";

    static {
        // Add BouncyCastle if not present
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    private RSAPrivateCrtKey rootKey;
    private X509Certificate rootCert;
    private RSAPrivateCrtKey esteidKey;
    private X509Certificate esteidCert;

    public void generate() throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, NoSuchProviderException,
            SignatureException, IOException, ParseException, OperatorCreationException, CertificateException {
        System.out.println("Generating CA ...");
        // Root
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyGen.initialize(2048);
        KeyPair root = keyGen.generateKeyPair();
        // Intermediate
        keyGen.initialize(4096);
        KeyPair esteid = keyGen.generateKeyPair();

        rootKey = (RSAPrivateCrtKey) root.getPrivate();
        esteidKey = (RSAPrivateCrtKey) esteid.getPrivate();

        rootCert = makeRootCert(root);
        esteidCert = makeEsteidCert(esteid, root);
    }

    public X509Certificate getIntermediateCert() {
        return esteidCert;
    }

    public X509Certificate getRootCert() {
        return rootCert;
    }

    static X509CertificateHolder getRealCert(String path) throws IOException {
        try (PEMParser pem = new PEMParser(new InputStreamReader(FakeEstEIDCA.class.getResourceAsStream(path), "UTF-8"))) {
            X509CertificateHolder crt = (X509CertificateHolder) pem.readObject();
            return crt;
        }
    }

    private X509Certificate makeRootCert(KeyPair kp) throws InvalidKeyException, IllegalStateException, NoSuchProviderException,
            SignatureException, IOException, NoSuchAlgorithmException, ParseException, OperatorCreationException, CertificateException {

        // Load real root certificate
        X509CertificateHolder real = getRealCert("sk-root.pem");

        // Use values from real certificate
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(real.getIssuer(), real.getSerialNumber(), Time.getInstance(new ASN1GeneralizedTime(real.getNotBefore())), Time.getInstance(new ASN1GeneralizedTime(real.getNotAfter())), real.getSubject(), kp.getPublic());

        @SuppressWarnings("unchecked")
        List<ASN1ObjectIdentifier> list = real.getExtensionOIDs();

        // Copy all extensions verbatim
        for (ASN1ObjectIdentifier extoid : list) {
            Extension ext = real.getExtension(extoid);
            builder.copyAndAddExtension(ext.getExtnId(), ext.isCritical(), real);
        }

        // Generate cert
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(kp.getPrivate());

        X509CertificateHolder cert = builder.build(sigGen);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(cert);
    }

    private X509Certificate makeEsteidCert(KeyPair esteid, KeyPair root) throws InvalidKeyException, IllegalStateException,
            NoSuchProviderException, SignatureException, IOException, NoSuchAlgorithmException, ParseException, OperatorCreationException,
            CertificateException {

        // Load current root certificate
        X509CertificateHolder real = getRealCert("sk-esteid.pem");

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(real.getIssuer(), real.getSerialNumber(),
                Time.getInstance(new ASN1UTCTime(real.getNotBefore())), Time.getInstance(new ASN1GeneralizedTime(real.getNotAfter())), real.getSubject(), esteid.getPublic());

        // Basic constraints
        @SuppressWarnings("unchecked")
        List<ASN1ObjectIdentifier> list = real.getExtensionOIDs();

        // Copy all extensions
        for (ASN1ObjectIdentifier extoid : list) {
            Extension ext = real.getExtension(extoid);
            builder.copyAndAddExtension(ext.getExtnId(), ext.isCritical(), real);
        }

        // Generate cert
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA384withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(root.getPrivate());

        X509CertificateHolder cert = builder.build(sigGen);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(cert);
    }

    public X509Certificate generateUserCertificate(PublicKey pubkey, boolean signature, String firstname, String lastname,
                                                   String idcode, String email, Date from, Date to) throws InvalidKeyException, ParseException, IOException, IllegalStateException,
            NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
        if (pubkey instanceof ECPublicKey) {
            return generateUserCertificate((ECPublicKey) pubkey, signature, firstname, lastname, idcode, email, from, to);
        } else if (pubkey instanceof RSAPublicKey) {
            return generateUserCertificate((RSAPublicKey) pubkey, signature, firstname, lastname, idcode, email, from, to);
        } else {
            throw new IllegalArgumentException("Unknown public key type " + pubkey.getAlgorithm());
        }
    }

    public X509Certificate cloneUserCertificate(PublicKey pubkey, X509Certificate cert) throws InvalidKeyException, ParseException, IOException, IllegalStateException,
            NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {
        if (pubkey instanceof ECPublicKey) {
            return cloneUserCertificate((ECPublicKey) pubkey, cert);
        } else if (pubkey instanceof RSAPublicKey) {
            return cloneUserCertificate((RSAPublicKey) pubkey, cert);
        } else {
            throw new IllegalArgumentException("Unknown public key type " + pubkey.getAlgorithm());
        }
    }

    private X509Certificate cloneUserCertificate(RSAPublicKey pubkey, X509Certificate cert) throws OperatorCreationException, CertificateException, IOException {
        if (pubkey.getModulus().bitLength() != 2048) {
            throw new IllegalArgumentException("Key must be 2048b RSA");
        }
        X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
        // Clone everything
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(holder.getIssuer(), cert.getSerialNumber(), cert.getNotBefore(), cert.getNotAfter(), holder.getSubject(), pubkey);
        @SuppressWarnings("unchecked")
        List<ASN1ObjectIdentifier> list = holder.getExtensionOIDs();

        // Copy all extensions
        for (ASN1ObjectIdentifier extoid : list) {
            Extension ext = holder.getExtension(extoid);
            builder.copyAndAddExtension(ext.getExtnId(), ext.isCritical(), holder);
        }
        // Generate cert. NB! SHA256!
        ContentSigner sigGen = new JcaContentSignerBuilder(cert.getSigAlgName()).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(esteidKey);

        X509CertificateHolder newcert = builder.build(sigGen);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(newcert);

    }


    private X509Certificate generateUserCertificate(RSAPublicKey pubkey, boolean signature, String firstname, String lastname,
                                                    String idcode, String email, Date from, Date to) throws InvalidKeyException, ParseException, IOException, IllegalStateException,
            NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {

        if (pubkey.getModulus().bitLength() != 2048) {
            throw new IllegalArgumentException("Key must be 2048b RSA");
        }
        Date startDate = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH).parse("2017-01-01");
        Date endDate = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH).parse("2017-12-31");

        if (from != null) {
            startDate = from;
        }
        if (to != null) {
            endDate = to;
        }
        String template = "C=EE,O=ESTEID,OU=%s,CN=%s\\,%s\\,%s,SURNAME=%s,GIVENNAME=%s,SERIALNUMBER=%s";
        // Normalize.
        lastname = lastname.toUpperCase();
        firstname = firstname.toUpperCase();
        idcode = idcode.toUpperCase();
        email = email.toLowerCase();
        String subject = String.format(template, (signature ? "digital signature" : "authentication"), lastname, firstname, idcode,
                lastname, firstname, idcode);

        byte[] serialBytes = new byte[16];
        SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
        rnd.nextBytes(serialBytes);
        serialBytes[0] &= 0x7F; // Can't be negative
        BigInteger serial = new BigInteger(serialBytes);

        X509CertificateHolder real;
        if (signature) {
            real = getRealCert("sk-sign.pem");
        } else {
            real = getRealCert("sk-auth.pem");
        }
        System.out.println("Generating from subject: " + real.getSubject());
        System.out.println("Generating subject: " + new X500Name(subject).toString());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(real.getIssuer(), serial, startDate, endDate, new X500Name(subject), pubkey);

        @SuppressWarnings("unchecked")
        List<ASN1ObjectIdentifier> list = real.getExtensionOIDs();

        // Copy all extensions, except altName
        for (ASN1ObjectIdentifier extoid : list) {
            Extension ext = real.getExtension(extoid);
            if (ext.getExtnId().equals(Extension.subjectAlternativeName)) {
                // altName must be changed
                builder.addExtension(ext.getExtnId(), ext.isCritical(), new GeneralNames(new GeneralName(GeneralName.rfc822Name, email)));
            } else {
                builder.copyAndAddExtension(ext.getExtnId(), ext.isCritical(), real);
            }
        }

        // Generate cert
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(esteidKey);

        X509CertificateHolder cert = builder.build(sigGen);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(cert);
    }

    // ECC versions
    private X509Certificate cloneUserCertificate(ECPublicKey pubkey, X509Certificate cert) throws OperatorCreationException, CertificateException, IOException {
        // FIXME: check actual curve
        if (pubkey.getParams().getCurve().getField().getFieldSize() != 384) {
            throw new IllegalArgumentException("Must be secp384r1 key!");
        }
        X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
        // Clone everything
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(holder.getIssuer(), cert.getSerialNumber(), cert.getNotBefore(), cert.getNotAfter(), holder.getSubject(), pubkey);
        @SuppressWarnings("unchecked")
        List<ASN1ObjectIdentifier> list = holder.getExtensionOIDs();

        // Copy all extensions
        for (ASN1ObjectIdentifier extoid : list) {
            Extension ext = holder.getExtension(extoid);
            builder.copyAndAddExtension(ext.getExtnId(), ext.isCritical(), holder);
        }
        // Generate cert. NB! SHA256!
        ContentSigner sigGen = new JcaContentSignerBuilder(cert.getSigAlgName()).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(esteidKey);

        X509CertificateHolder newcert = builder.build(sigGen);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(newcert);

    }

    private X509Certificate generateUserCertificate(ECPublicKey pubkey, boolean signature, String firstname, String lastname,
                                                    String idcode, String email, Date from, Date to) throws InvalidKeyException, ParseException, IOException, IllegalStateException,
            NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateException, OperatorCreationException {

        Date startDate = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH).parse("2017-01-01");
        Date endDate = new SimpleDateFormat("yyyy-MM-dd", Locale.ENGLISH).parse("2017-12-31");

        if (from != null) {
            startDate = from;
        }
        if (to != null) {
            endDate = to;
        }
        String template = "C=EE,O=ESTEID,OU=%s,CN=%s\\,%s\\,%s,SURNAME=%s,GIVENNAME=%s,SERIALNUMBER=%s";
        // Normalize.
        lastname = lastname.toUpperCase();
        firstname = firstname.toUpperCase();
        idcode = idcode.toUpperCase();
        email = email.toLowerCase();
        String subject = String.format(template, (signature ? "digital signature" : "authentication"), lastname, firstname, idcode,
                lastname, firstname, idcode);

        byte[] serialBytes = new byte[16];
        SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
        rnd.nextBytes(serialBytes);
        serialBytes[0] &= 0x7F; // Can't be negative
        BigInteger serial = new BigInteger(serialBytes);

        X509CertificateHolder real;
        if (signature) {
            real = getRealCert("sk-sign-ecc.pem");
        } else {
            real = getRealCert("sk-auth-ecc.pem");
        }
        System.out.println("Generating from subject: " + real.getSubject());
        System.out.println("Generating subject: " + new X500Name(subject).toString());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(real.getIssuer(), serial, startDate, endDate, new X500Name(subject), pubkey);

        @SuppressWarnings("unchecked")
        List<ASN1ObjectIdentifier> list = real.getExtensionOIDs();

        // Copy all extensions, except altName
        for (ASN1ObjectIdentifier extoid : list) {
            Extension ext = real.getExtension(extoid);
            if (ext.getExtnId().equals(Extension.subjectAlternativeName)) {
                // altName must be changed
                builder.addExtension(ext.getExtnId(), ext.isCritical(), new GeneralNames(new GeneralName(GeneralName.rfc822Name, email)));
            } else {
                builder.copyAndAddExtension(ext.getExtnId(), ext.isCritical(), real);
            }
        }

        // Generate cert
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA256withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(esteidKey);

        X509CertificateHolder cert = builder.build(sigGen);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(cert);
    }


    public void storeToFile(File f) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException,
            IOException {
        try (OutputStream out = new FileOutputStream(f)) {
            KeyStore keystore = KeyStore.getInstance("pkcs12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(null, password);
            keystore.setKeyEntry(root, rootKey, password, new Certificate[]{rootCert});
            keystore.setKeyEntry(esteid, esteidKey, password, new Certificate[]{esteidCert});
            keystore.store(out, password);
        }
    }

    public void loadFromFile(File f) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException,
            IOException, UnrecoverableKeyException {
        try (InputStream in = new FileInputStream(f)) {
            KeyStore keystore = KeyStore.getInstance("pkcs12", BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(in, password);
            rootKey = (RSAPrivateCrtKey) keystore.getKey(root, password);
            rootCert = (X509Certificate) keystore.getCertificate(root);
            esteidKey = (RSAPrivateCrtKey) keystore.getKey(esteid, password);
            esteidCert = (X509Certificate) keystore.getCertificate(esteid);
        }
    }

    public static X509Certificate holder2pem(X509CertificateHolder holder) throws CertificateException {
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(holder);
    }
}
