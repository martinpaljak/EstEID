package org.esteid;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

public class EstEIDSelfTests {

    final X509Certificate authcert;
    final X509Certificate signcert;
    final EstEID esteid;
    final CallbackHandler cb;

    final SecureRandom rnd;
    public EstEIDSelfTests(EstEID esteid, CallbackHandler cb) throws IOException , NoSuchAlgorithmException{
        this.esteid = esteid;
        this.authcert = esteid.getAuthenticationCertificate();
        this.signcert = esteid.getSigningCertificate();
        this.cb = cb;
        rnd = SecureRandom.getInstance("SHA1PRNG");
    }


    public void crypto_tests() throws WrongPINException, EstEIDException, IOException, UnsupportedCallbackException {

        System.out.println("Testing certificates and crypto ...");

        try {
            // Authentication key

            System.out.println("Auth cert: " + authcert.getSubjectDN());

            if (authcert.getPublicKey().getAlgorithm().equals("EC")) {
                Signature v = Signature.getInstance("NONEwithECDSA", "BC");
                byte[] hash = new byte[0x30];
                rnd.nextBytes(hash);

                v.initVerify(authcert.getPublicKey());
                v.update(hash);
                if (!v.verify(BaseEstEID.rs2der(esteid.authenticate(hash, cb)))) {
                    throw new EstEIDException("Card and auth key don't match on authentication!");
                } else {
                    System.out.println("AUTHENTICATE: OK");
                }

                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec("secp384r1")); // FIXME: from certificate
                KeyPair ephemeral = generator.generateKeyPair();

                ka.init(ephemeral.getPrivate());
                ka.doPhase(authcert.getPublicKey(), true);
                byte[] host_secret = ka.generateSecret();
                byte[] card_secret = esteid.dh((ECPublicKey) ephemeral.getPublic(), cb);

                if (!java.util.Arrays.equals(card_secret, host_secret)) {
               //     throw new EstEIDException("Card and auth key don't match!");
                } else {
                 //   System.out.println("KEY AGREEMENT: OK");
                }
            } else if (authcert.getPublicKey().getAlgorithm().equals("RSA")) {
                // Verify on-card keys vs certificates
                Cipher verify_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                byte[] hash = new byte[20];

                rnd.nextBytes(hash);
                verify_cipher.init(Cipher.DECRYPT_MODE, authcert.getPublicKey());
                byte[] result = verify_cipher.doFinal(esteid.authenticate(hash, cb));
                if (!java.util.Arrays.equals(hash, result)) {
                    throw new EstEIDException("Card and auth key don't match!");
                } else {
                    System.out.println("ENCRYPT: OK");
                }

                rnd.nextBytes(hash);
                verify_cipher.init(Cipher.ENCRYPT_MODE, authcert.getPublicKey());
                result = verify_cipher.doFinal(hash);
                if (!java.util.Arrays.equals(hash, esteid.decrypt(result, cb))) {
                    throw new EstEIDException("Card and auth key don't match on decryption!");
                } else {
                    System.out.println("DECRYPT: OK");
                }
            }

            // Signature key

            System.out.println("Sign cert: " + signcert.getSubjectDN());

            if (signcert.getPublicKey().getAlgorithm().equals("EC")) {
                Signature v = Signature.getInstance("NONEwithECDSA", "BC");
                byte[] hash = new byte[0x30];
                rnd.nextBytes(hash);
                v.initVerify(signcert.getPublicKey());
                v.update(hash);
                if (!v.verify(BaseEstEID.rs2der(esteid.sign(hash, cb)))) {
                    throw new EstEIDException("Card and sign key don't match on signing!");
                } else {
                    System.out.println("SIGN: OK");
                }
            } else if (signcert.getPublicKey().getAlgorithm().equals("RSA")) {
                // TODO: different hash sizes
                // Verify on-card keys vs certificates
                Cipher verify_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                byte[] hash = new byte[20];
                rnd.nextBytes(hash);
                verify_cipher.init(Cipher.DECRYPT_MODE, signcert.getPublicKey());
                byte[] result = verify_cipher.doFinal(esteid.sign(hash, cb));
                if (!java.util.Arrays.equals(hash, result)) {
                    throw new EstEIDException("Card and sign key don't match on signing!");
                } else {
                    System.out.println("SIGN: OK");
                }
            }
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            System.out.println("FAILURE");
        }
    }

//    public void pin_tests(String pin1, String pin2, String puk) throws IOException, LegacyEstEID.WrongPINException, EstEIDException {
//
//        Map<LegacyEstEID.PIN, Byte> retries = getPINCounters();
//        if (retries.get(PIN1) < 3 || retries.get(PIN2) < 3 || retries.get(PUK) < 3) {
//            throw new IllegalStateException("Will not run pin tests on a card with not-known or blocked PINs!");
//        }
//        System.out.println("Testing PIN codes ...");
//        String newpin1 = make_random_pin(4);
//        String newpin2 = make_random_pin(5);
//        String newpuk = make_random_pin(8);
//
//        // Verify all PIN-s
//        verify(PIN1, pin1);
//        verify(PIN2, pin2);
//        verify(PUK, puk);
//        System.out.println("VERIFY: OK");
//
//        // Change all pins to new and back
//        change(PIN1, pin1, newpin1);
//        change(PIN1, newpin1, pin1);
//
//        change(PIN2, pin2, newpin2);
//        change(PIN2, newpin2, pin2);
//
//        change(PUK, puk, newpuk);
//        change(PUK, newpuk, puk);
//        System.out.println("CHANGE: OK");
//
//        // Block pin1 and pin2 and unblock with PUK
//        for (LegacyEstEID.PIN p : Arrays.asList(PIN1, PIN2)) {
//            for (int i = 0; i < 3; i++) {
//                try {
//                    verify(p, make_random_pin(p.max));
//                } catch (LegacyEstEID.WrongPINException e) {
//                    System.out.println("Expected exception: " + e.toString());
//                }
//            }
//        }
//
//        // Verify PUK and unblock PIN2
//        verify(PUK, puk);
//        unblock(PIN1);
//        // Unblock PIN2
//        verify(PUK, puk);
//        unblock(PIN2);
//        System.out.println("UNBLOCK: OK");
//    }

}
