package org.esteid;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

public interface EstEID {

    enum CardType {
        MICARDO, DigiID, JavaCard2011, AnyJavaCard, IASECC2018;
    }

    enum PIN {
        PIN1, PIN2, PUK
    }

    enum CERT {
        AUTH, SIGN
    }

    X509Certificate getCertificate(CERT type);

    X509Certificate getAuthenticationCertificate();

    X509Certificate getSigningCertificate();

    byte[] sign(byte[] hash, CallbackHandler cb) throws WrongPINException, UnsupportedCallbackException, IOException;

    byte[] authenticate(byte[] hash, CallbackHandler cb) throws WrongPINException, UnsupportedCallbackException, IOException;

    byte[] decrypt(byte[] cgram, CallbackHandler cb) throws WrongPINException, UnsupportedCallbackException, IOException;

    byte[] dh(ECPublicKey pk, CallbackHandler cb) throws WrongPINException, UnsupportedCallbackException, IOException;

    int getPINCounter(PIN pin);

    int getKeyCounter();

    String getPersonalDataField(int record);

    boolean changePIN(PIN pin, CallbackHandler cb) throws WrongPINException, UnsupportedCallbackException;

    boolean unblockPIN(PIN pin, CallbackHandler cb) throws WrongPINException, UnsupportedCallbackException, IOException;
}
