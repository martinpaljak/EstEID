package org.esteid.jca;

import apdu4j.LoggingCardTerminal;
import apdu4j.TerminalManager;
import org.esteid.EstEID;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CardDelegate extends AbstractDelegate {
    private final boolean sign;
    private final EstEID e;
    private final NotificationInterface notify;

    protected CardDelegate(CardChannel channel, boolean sign, NotificationInterface notify) {
        e = EstEID.getInstance(channel);
        this.sign = sign;
        this.notify = notify;
    }

    public static CardDelegate any(boolean sign, NotificationInterface console) throws CardException {
        CardTerminal t = TerminalManager.getTheReader();
        t = LoggingCardTerminal.getInstance(t);
        Card c = t.connect("*");
        return new CardDelegate(c.getBasicChannel(), sign, console == null ? CONSOLE : console);
    }

    @Override
    public X509Certificate readCertificate() throws CertificateException {
        try {
            return sign ? e.readSignCert() : e.readAuthCert();
        } catch (CardException | EstEID.EstEIDException e) {
            throw new CertificateException("Failed to read certificate", e);
        }
    }

    @Override
    public byte[] getSignature(byte[] dtbs, String algorithm) throws SignatureException {

        try {
            if (!algorithm.equals("NONEwithRSA")) {
                MessageDigest md = MessageDigest.getInstance(AbstractDelegate.hashAlgos.get(algorithm));

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(AbstractDelegate.digestInfos.get(algorithm));
                baos.write(md.digest(dtbs));
                dtbs = baos.toByteArray();
            }
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            throw new SignatureException("No hash", e);
        }

        try {
            String pin = notify.askPinCode("Please enter PIN" + (sign ? "2" : "1"));
            return sign ? e.sign(dtbs, pin) : e.authenticate(dtbs, pin);
        } catch (CardException | EstEID.EstEIDException | EstEID.WrongPINException e) {
            throw new SignatureException("Failed to sign", e);
        }
    }

    @Override
    public String getName() {
        return "javax.smartcardio";
    }

}
