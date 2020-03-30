package org.esteid;

import apdu4j.*;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

// For 2018 IDEMIA IAS ECC
public class EUREstEID extends BaseEstEID {
    private static final byte[] AWP_AID = HexUtils.hex2bin("A000000077010800070000FE00000100");
    private static final byte[] AUTH_AID = HexUtils.hex2bin("E828BD080FF2504F5420415750");
    private static final byte[] QSCD_AID = HexUtils.hex2bin("51534344204170706C69636174696F6E");

    private static final int PIN1_REF = 0x01;
    private static final int PIN2_REF = 0x85;


    public EUREstEID(BIBO bibo) {
        super(bibo);
    }

    @Override
    byte[] readCertificate(CERT type) {
        // Select Master File
        check(transmit(new CommandAPDU(0x00, 0xA4, 0x00, 0x0C)));
        // Select Auth cert
        check(transmit(new CommandAPDU(0x00, 0xA4, 0x01, 0x0C, new byte[]{(byte) 0xAD, type == CERT.SIGN ? (byte) 0xF2 : (byte) 0xF1})));
        check(transmit(new CommandAPDU(0x00, 0xA4, 0x02, 0x0C, new byte[]{0x34, type == CERT.SIGN ? (byte) 0x1F : (byte) 0x01})));
        return readCert(channel);
    }

    public byte[] getDocumentNumber() {


        //select(AWP_AID);

        // Select Perso File
        ResponseAPDU r = transmit(new CommandAPDU(0x00, 0xA4, 0x01, 0x0C, new byte[]{0x50, 0x00}));
        check(r);

        for (PersonalData pd : PersonalData.values()) {
            transmit(new CommandAPDU(0x00, 0xA4, 0x01, 0x0C, new byte[]{0x50, pd.getRec()}));
            ResponseAPDU resp = transmit(new CommandAPDU(0x00, 0xB0, 0x00, 0x00, 256));
            if (resp.getSW() == 0x9000) {
                byte[] v = resp.getData();
                if (v.length == 1 && v[0] == 0x00) {
                    System.out.printf("%s:%n", pd.name());
                } else
                    System.out.format("%s: %s%n", pd.name(), new String(resp.getData(), StandardCharsets.UTF_8));
            }
        }
        return null;
    }


    public static byte[] formatPIN(String v) {
        byte[] pl = new byte[12];
        Arrays.fill(pl, (byte) 0xFF);
        byte[] pin = v.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(pin, 0, pl, 0, pin.length);
        return pl;
    }

    public boolean verifyPIN(PIN pin, CallbackHandler cb) throws IOException, UnsupportedCallbackException {
        if (pin == PIN.PIN1) {
            select(AWP_AID);
        } else if (pin == PIN.PIN2) {
            select(QSCD_AID);
        }
        byte[] pl = new byte[12];
        Arrays.fill(pl, (byte) 0xFF);
        PasswordCallback pincb = new PasswordCallback(pin.name(), false);
        cb.handle(new Callback[]{pincb});
        byte[] pinv = new String(pincb.getPassword()).getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(pinv, 0, pl, 0, pinv.length);
        // Clear sensitive values
        Arrays.fill(pinv, (byte) 0);
        pincb.clearPassword();
        int ref = 0;
        if (pin == PIN.PIN1) {
            ref = PIN1_REF;
        } else if (pin == PIN.PIN2) {
            ref = PIN2_REF;
        } else {
            throw new IllegalArgumentException("Verify can't handle " + pin);
        }
        CommandAPDU verify = new CommandAPDU(0x00, 0x20, 0x00, ref, pl);
        ResponseAPDU response = channel.transmit(verify);
        EstEIDException.check(response, pin.name() + " verify", 0x9000, 0x63C2, 0x63C1, 0x63C0);
        if (response.getSW() == 0x9000)
            return true;
        return false;
    }


    @Override
    public byte[] authenticate(byte[] v, CallbackHandler cb) throws IOException, UnsupportedCallbackException {
        verifyPIN(PIN.PIN1, cb);
        select(AUTH_AID);
        System.out.println("Signature payload: " + HexUtils.bin2hex(v));
        CommandAPDU setenv = new CommandAPDU(HexUtils.hex2bin("002241A4098004FF200800840181"));
        check(channel.transmit(setenv));
        byte[] signature = check(channel.transmit(new CommandAPDU(0x00, 0x88, 0x00, 0x00, v, 256))).getData();
        System.out.println("Signature: " + HexUtils.bin2hex(signature));
        return signature;
    }

    @Override
    public byte[] dh(ECPublicKey pk, CallbackHandler cb) throws IOException, UnsupportedCallbackException {
        return new byte[0];
    }

    public byte[] sign(byte[] v, CallbackHandler cb) throws UnsupportedCallbackException, IOException {
        select(QSCD_AID);
        verifyPIN(PIN.PIN2, cb);
        CommandAPDU setenv = new CommandAPDU(HexUtils.hex2bin("002241B6098004FF15080084019F"));
        check(channel.transmit(setenv));
        byte[] signature = check(channel.transmit(new CommandAPDU(0x00, 0x2A, 0x9E, 0x9A, v, 256))).getData();
        return signature;
    }

    @Override
    public int getPINCounter(PIN p) {
        // check for pinpad
        return 0;
    }

    @Override
    public boolean unblockPIN(PIN pin, CallbackHandler cb) throws WrongPINException, UnsupportedCallbackException {
        return false;
    }


    byte[] readCert(APDUBIBO c) {
        // 233 is the empirical for reading from NFC
        int chunksize = 233;
        ResponseAPDU resp = check(c.transmit(new CommandAPDU(0x00, 0xB0, 0x00, 0x00, chunksize)));
        if (resp.getBytes()[0] != (byte) 0x30 || resp.getBytes()[1] != (byte) 0x82)
            return null;
        int size = (((resp.getBytes()[2] & 0xFF) << 8) | (resp.getBytes()[3] & 0xFF)) + 4;
        byte[] data = new byte[size];
        System.arraycopy(resp.getData(), 0, data, 0, resp.getData().length);
        for (int offset = resp.getData().length; offset < size; offset += resp.getData().length) {
            resp = check(c.transmit(new CommandAPDU(0x00, 0xB0, offset >> 8, offset & 0xFF, Math.min(size - offset, chunksize))));
            System.arraycopy(resp.getData(), 0, data, offset, resp.getData().length);
        }
        return data;
    }


    // Personal data file records
    public enum PersonalData {
        SURNAME(1),
        GIVEN_NAMES(2),
        SEX(3),
        CITIZENSHIP(4),
        DATE_OF_BIRTH(5),
        PERSONAL_ID(6),
        DOCUMENT_NR(7),
        EXPIRY_DATE(8),
        ISSUING_DATE(9),
        PERMIT_TYPE(10),
        REMARK1(11),
        REMARK2(12),
        REMARK3(13),
        REMARK4(14),
        REMARK5(15);
        private final int rec;

        PersonalData(int recno) {
            this.rec = recno;
        }

        // Record in file
        public byte getRec() {
            return (byte) rec;
        }
    }

    public static byte[] getAwpAid() {
        return AWP_AID.clone();
    }
}
