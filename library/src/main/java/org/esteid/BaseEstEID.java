package org.esteid;

import apdu4j.APDUBIBO;
import apdu4j.BIBO;
import apdu4j.CommandAPDU;
import apdu4j.ResponseAPDU;
import org.bouncycastle.asn1.*;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

// High level interface of Estonian ID-cards
// Caller needs to provide APDU channel and provide necessary locking etc.
public abstract class BaseEstEID implements EstEID {
    protected X509Certificate authCert;
    protected X509Certificate signCert;

    protected final APDUBIBO channel;

    protected BaseEstEID(BIBO bibo) {
        if (bibo instanceof APDUBIBO)
            this.channel = (APDUBIBO) bibo;
        else
            this.channel = new APDUBIBO(bibo);
    }

    abstract byte[] readCertificate(CERT type);

    // Keeps the data
    //private HashMap<Integer, String> personalData = new HashMap<>();

    @Override
    public X509Certificate getCertificate(CERT type) {
        switch (type) {
            case AUTH:
                return getAuthenticationCertificate();
            case SIGN:
                return getSigningCertificate();
            default:
                throw new RuntimeException("Invalid enum");
        }
    }

    @Override
    public X509Certificate getAuthenticationCertificate() {
        if (authCert == null)
            authCert = bytes2cert(readCertificate(CERT.AUTH));
        return authCert;
    }

    @Override
    public X509Certificate getSigningCertificate() {
        if (signCert == null)
            signCert = bytes2cert(readCertificate(CERT.SIGN));
        return signCert;
    }

    @Override
    public boolean changePIN(PIN pin, CallbackHandler cb) {
        return false;
    }

    @Override
    public byte[] decrypt(byte[] cgram, CallbackHandler cb) throws WrongPINException, UnsupportedCallbackException, IOException {
        return new byte[0];
    }

    @Override
    public int getPINCounter(PIN pin) {
        return -1;
    }

    @Override
    public int getKeyCounter() {
        return -1;
    }

    @Override
    public String getPersonalDataField(int record) {
        return null;
    }

    protected static ResponseAPDU check(ResponseAPDU r) throws EstEIDException {
        return EstEIDException.check(r);
    }

    // Provide access to underlying BIBO
    protected ResponseAPDU transmit(CommandAPDU command) {
        return channel.transmit(command);
    }

    // Implementations
    private static X509Certificate bytes2cert(byte[] v) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(v));
        } catch (CertificateException e) {
            throw new RuntimeException("could not parse certificate: " + e.getMessage(), e);
        }
    }

    protected void select(byte[] aid) {
        check(channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x0C, aid)));
    }

    // Convert the R||S representation back to DER (as used by Java)
    public static byte[] rs2der(byte[] rs) throws SignatureException {
        if (rs.length % 2 != 0) {
            throw new IllegalArgumentException("R||S representation must be even bytes: " + rs.length);
        }
        try {
            byte[] r = Arrays.copyOfRange(rs, 0, rs.length / 2);
            byte[] s = Arrays.copyOfRange(rs, rs.length / 2, rs.length);
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            ASN1OutputStream ders = ASN1OutputStream.create(bo, ASN1Encoding.DER);
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(new BigInteger(1, r)));
            v.add(new ASN1Integer(new BigInteger(1, s)));
            ders.writeObject(new DERSequence(v));
            return bo.toByteArray();
        } catch (IOException e) {
            throw new SignatureException("Can not convert R||S to DER: " + e.getMessage());
        }
    }
}
