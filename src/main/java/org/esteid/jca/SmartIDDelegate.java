package org.esteid.jca;

import ee.sk.smartid.*;
import ee.sk.smartid.rest.dao.NationalIdentity;
import org.esteid.hacker.CLI;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.*;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class SmartIDDelegate extends AbstractDelegate {
    private static final Map<String, HashType> hashAlgosSmart = new HashMap<>();

    static {
        hashAlgosSmart.put("SHA256withRSA", HashType.SHA256);
        hashAlgosSmart.put("SHA384withRSA", HashType.SHA384);
        hashAlgosSmart.put("SHA512withRSA", HashType.SHA512);
    }

    final String uuid;
    final String name;
    final String countrycode;
    final String idcode;
    final SmartIdClient client;
    final NationalIdentity nationalIdentity;
    final NotificationInterface notify;
    private String documentNumber = null;
    private boolean sign = false;

    private SmartIDDelegate(String uuid, String name, String countrycode, String idcode, boolean sign, NotificationInterface notify) {
        this.uuid = uuid;
        this.name = name;
        this.countrycode = countrycode;
        this.idcode = idcode;
        nationalIdentity = new NationalIdentity(countrycode, idcode);

        client = new SmartIdClient();
        if (uuid == null && name == null) {
            client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v1/");
            client.setRelyingPartyName("DEMO");
            client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
        } else {
            client.setHostUrl("https://rp-api.smart-id.com/v1/");
            client.setRelyingPartyUUID(uuid);
            client.setRelyingPartyName(name);
        }
        this.sign = sign;
        this.notify = notify;
    }


    public static SmartIDDelegate withFixedCertificate(String uuid, String name, X509Certificate cert, NotificationInterface notify) {
        String idcode = null;
        String countrycode = null;
        boolean sign;

        try {
            LdapName ldapDN = new LdapName(cert.getSubjectX500Principal().getName());
            for (Rdn rdn : ldapDN.getRdns()) {
                if (rdn.getType().equals("2.5.4.5")) {
                    byte[] v = (byte[]) rdn.getValue();
                    String serialNumber = new String(Arrays.copyOfRange(v, 2, v.length), "UTF-8");
                    System.out.println("Serial: " + serialNumber);
                    idcode = serialNumber.substring(6, serialNumber.length());
                    countrycode = serialNumber.substring(3, 5);
                    break;
                }
            }

            if (idcode == null || countrycode == null)
                throw new IllegalArgumentException("Certificate must be for SmartID");

            // TLS client EKU
            if (cert.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2")) {
                sign = false;
            } else {
                sign = true;
            }
            SmartIDDelegate sid = new SmartIDDelegate(uuid, name, countrycode, idcode, sign, notify);
            sid.cert = cert;
            return sid;
        } catch (InvalidNameException | UnsupportedEncodingException | CertificateParsingException e) {
            //e.printStackTrace();
            throw new RuntimeException("Could not initialize SmartID provider: " + e.getMessage(), e);
        }
    }

    public static SmartIDDelegate forPerson(String uuid, String name, String countrycode, String idcode, boolean sign, NotificationInterface notify) {
        return new SmartIDDelegate(uuid, name, countrycode, idcode, sign, notify);
    }

    @Override
    public X509Certificate readCertificate() throws CertificateException {
        // Get
        if (sign == false) {
            AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();

            String verificationCode = authenticationHash.calculateVerificationCode();
            notify.showControlCode(verificationCode);
            SmartIdAuthenticationResponse authenticationResponse = client
                    .createAuthentication()
                    .withNationalIdentity(nationalIdentity)
                    .withAuthenticationHash(authenticationHash)
                    .withDisplayText("This is NOT the signature")
                    .authenticate();
            cert = authenticationResponse.getCertificate();
        } else {
            SmartIdCertificate certificateResponse = client
                    .getCertificate()
                    .withNationalIdentity(nationalIdentity)
                    .fetch();
            cert = certificateResponse.getCertificate();
            documentNumber = certificateResponse.getDocumentNumber();
            System.out.println("Document number: " + documentNumber);
            return cert;
        }
        //System.out.println("Using certificate:");
        System.out.println(CLI.crt2pem(cert));
        return cert;
    }

    @Override
    public byte[] getSignature(byte[] dtbs, String algorithm) throws SignatureException {
        // Check
        if (!hashAlgos.containsKey(algorithm)) {
            throw new SignatureException("Smart ID does not support " + algorithm + " algorithm");
        }

        // Hash
        try {
            MessageDigest md = MessageDigest.getInstance(hashAlgos.get(algorithm));
            dtbs = md.digest(dtbs);
        } catch (GeneralSecurityException e) {
            throw new SignatureException("Could not hash", e);
        }

        final byte[] result;
        if (sign) {
            SignableHash hash = new SignableHash();
            hash.setHashType(hashAlgosSmart.get(algorithm));
            hash.setHash(dtbs);

            notify.showControlCode(hash.calculateVerificationCode());

            SmartIdSignature smartIdSignature = client
                    .createSignature().withDisplayText("Technical signing")
                    .withDocumentNumber(documentNumber)
                    .withSignableHash(hash)
                    .sign();
            result = smartIdSignature.getValue();
        } else {
            AuthenticationHash hash = new AuthenticationHash();
            hash.setHashType(hashAlgosSmart.get(algorithm));
            hash.setHash(dtbs);

            notify.showControlCode(hash.calculateVerificationCode());
            SmartIdAuthenticationResponse authenticationResponse = client
                    .createAuthentication()
                    .withNationalIdentity(nationalIdentity)
                    .withAuthenticationHash(hash)
                    .withDisplayText("Technical signing")
                    .authenticate();
            result = authenticationResponse.getSignatureValue();
        }
        //System.out.println("SmartID signature is " + HexUtils.bin2hex(result));
        return result;
    }

    @Override
    public String getName() {
        return "SmartID";
    }

}
