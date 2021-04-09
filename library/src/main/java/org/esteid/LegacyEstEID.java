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
package org.esteid;

import apdu4j.core.APDUBIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.HexUtils;
import apdu4j.core.ResponseAPDU;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

// For Micardo and derived
public final class LegacyEstEID extends BaseEstEID implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(LegacyEstEID.class);

    // Commands
    public final static int INS_SELECT = 0xA4;
    public final static int INS_READ_BINARY = 0xB0;
    public final static int INS_READ_RECORD = 0xB2;
    public final static int INS_VERIFY = 0x20;
    public final static int INS_CHANGE_REFERENCE_DATA = 0x24;
    public final static int INS_RESET_RETRY_COUNTER = 0x2C;
    public final static int INS_GET_DATA = 0xCA;
    public final static int INS_MANAGE_SECURITY_ENVIRONMENT = 0x22;
    public final static int INS_PERFORM_SECURITY_OPERATION = 0x2A;
    public final static int INS_INTERNAL_AUTHENTICATE = 0x88;
    public final static int P1P2_PSO_SIGN = 0x9E9A;
    public final static int P1_PSO_SIGN = 0x9E;
    public final static int P2_PSO_SIGN = 0x9A;
    public final static int P1P2_PSO_DECRYPT = 0x8086;
    public final static int P1_PSO_DECRYPT = 0x80;
    public final static int P2_PSO_DECRYPT = 0x86;
    // File identifiers
    public final static int FID_3F00 = 0x3F00;
    public final static int FID_0013 = 0x0013;
    public final static int FID_0016 = 0x0016;
    public final static int FID_EEEE = 0xEEEE;
    public final static int FID_5044 = 0x5044;
    public final static int FID_AACE = 0xAACE;
    public final static int FID_DDCE = 0xDDCE;
    public final static int FID_0033 = 0x0033;
    // Shorthands
    public static final LegacyPIN PIN1 = LegacyPIN.PIN1;
    public static final LegacyPIN PIN2 = LegacyPIN.PIN2;
    public static final LegacyPIN PUK = LegacyPIN.PUK;
    // default test card PIN codes from envelope "1" ("00000000001")
    public static final String PIN1String = "0090";
    public static final String PIN2String = "01497";
    public static final String PUKString = "17258403";
    // should be 255 all the time!
    public final static int chunksize = 250;
    public static final String AID = "D23300000045737445494420763335";
    // AID of modern JavaCard app (FakeEstEID et al) National prefix of Estonia + "EstEID v3.5"
    private static final byte[] aid = HexUtils.hex2bin(AID);

    // Instance fields
    private CardType type = null;
    private int currentFID = FID_3F00;

    private LegacyEstEID(APDUBIBO c) {
        super(c);
    }

    public static LegacyEstEID getInstance(APDUBIBO c) {
        return new LegacyEstEID(c);
    }


    @Deprecated
    public static CardType identify(CardTerminal t) throws CardException, IOException {
        return CardType.AnyJavaCard;
        /*
        Card card = t.connect("*");
        card.beginExclusive();
        try {
            ATR atr = card.getATR();
            // Check for ATR.
            if (DesktopEstEID.knownATRs.containsKey(atr)) {
                // DigiID is a broken card (fixed to Micardo cold ATR)
                if (Arrays.equals(atr.getBytes(), HexUtils.hex2bin("3bfe9400ff80b1fa451f034573744549442076657220312e3043"))) {
                    // Check if DigiID or Micardo
                    ResponseAPDU resp = CardChannelBIBO.getBIBO(card.getBasicChannel()).transmit(new CommandAPDU(0x00, 0xA4, 0x02, 0x00, new byte[]{0x3F, 0x00}, 256));
                    if (resp.getSW() == 0x9000) {
                        // This also selected MF
                        return CardType.DigiID;
                    }
                    if (resp.getSW() == 0x6A83 || resp.getSW() == 0x6D00) {
                        // Locked up DigiID, reset card
                        card.disconnect(true);
                        card = t.connect("*");
                        card.beginExclusive();
                        return CardType.DigiID;
                    }
                }
                return DesktopEstEID.knownATRs.get(atr);
            }

            // Check for generic modern Applet if ATR is unknown
            ResponseAPDU resp = CardChannelBIBO.getBIBO(card.getBasicChannel()).transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid));
            if (resp.getSW() == 0x9000) {
                return CardType.AnyJavaCard;
            }
        } finally {
            card.endExclusive();
        }
        // If we get here this is not our card.
        return null;
         */
    }


    public static CommandAPDU select_apdu(int fid, boolean fci) {
        int p2 = fci ? 0x04 : 0x0C;
        byte[] fidbytes = new byte[2];
        fidbytes[0] = (byte) (fid >> 8);
        fidbytes[1] = (byte) (fid);

        if (fid == FID_3F00) { // Select master file
            return new CommandAPDU(0x00, INS_SELECT, 0x00, p2);
        } else if (fid == FID_EEEE) { // Select DF
            return new CommandAPDU(0x00, INS_SELECT, 0x01, p2, fidbytes);
        } else { // Select EF
            return new CommandAPDU(0x00, INS_SELECT, 0x02, p2, fidbytes);
        }
    }


    public static CommandAPDU read_record_apdu(byte recno) {
        return new CommandAPDU(0x00, INS_READ_RECORD, recno, 0x04, 256);
    }


    // PIN handling
    public static CommandAPDU verify_apdu(LegacyPIN pin, String value) {
        return new CommandAPDU(0x00, INS_VERIFY, 0x00, pin.getRef(), value.getBytes(StandardCharsets.US_ASCII));
    }


    public ResponseAPDU verify_cmd(LegacyPIN pin, String value) throws IOException, WrongPINException, EstEIDException {
        if (value.length() < pin.min || value.length() > pin.max)
            throw new IllegalArgumentException("PIN has incorrect length: " + value.length());
        ResponseAPDU r = transmit(verify_apdu(pin, value));
        WrongPINException.check(r);
        return EstEIDException.check(r);
    }


    public void verifyPIN(EstEID.PIN pin, CallbackHandler cb) throws IOException, UnsupportedCallbackException, WrongPINException {
        PasswordCallback pincb = new PasswordCallback(pin.name(), false);
        cb.handle(new Callback[]{pincb});
        byte[] pinv = new String(pincb.getPassword()).getBytes(StandardCharsets.US_ASCII);
        // Clear sensitive values
        Arrays.fill(pinv, (byte) 0);
        pincb.clearPassword();
        int ref = 0;
        if (pin == EstEID.PIN.PIN1) {
            ref = PIN1.ref;
        } else if (pin == EstEID.PIN.PIN2) {
            ref = PIN2.ref;
        } else {
            throw new IllegalArgumentException("Verify can't handle " + pin);
        }
        ResponseAPDU r = transmit(new CommandAPDU(0x00, INS_VERIFY, 0x00, ref, pinv));
        WrongPINException.check(r);
    }


    public void verify(LegacyPIN pin, String value) throws WrongPINException, IOException, EstEIDException {
        verify_cmd(pin, value);
    }

    public void change(LegacyPIN pin, String oldpin, String newpin) throws WrongPINException, IOException, EstEIDException {
        ResponseAPDU r = change_apdu(pin, oldpin.getBytes(StandardCharsets.US_ASCII), newpin.getBytes(StandardCharsets.US_ASCII));
        WrongPINException.check(r);
        EstEIDException.check(r);
    }

    public void unblock(LegacyPIN pin) throws WrongPINException, IOException, EstEIDException {
        unblock(pin, null);
    }

    public void unblock(LegacyPIN pin, String newpin) throws WrongPINException, IOException, EstEIDException {
        ResponseAPDU r = unblock_apdu(pin, newpin == null ? null : newpin.getBytes(StandardCharsets.US_ASCII));
        WrongPINException.check(r);
        EstEIDException.check(r);
    }

    public ResponseAPDU change_apdu(LegacyPIN pin, byte[] oldpin, byte[] newpin) throws IOException {
        byte[] v = new byte[oldpin.length + newpin.length];
        System.arraycopy(oldpin, 0, v, 0, oldpin.length);
        System.arraycopy(newpin, 0, v, oldpin.length, newpin.length);
        return transmit(new CommandAPDU(0x00, INS_CHANGE_REFERENCE_DATA, 0x00, pin.getRef(), v));
    }

    public ResponseAPDU unblock_apdu(LegacyPIN pin, byte[] newpin) throws IOException {
        if (newpin == null) {
            return transmit(new CommandAPDU(0x00, INS_RESET_RETRY_COUNTER, 0x03, pin.getRef()));
        } else {
            return transmit(new CommandAPDU(0x00, INS_RESET_RETRY_COUNTER, 0x00, pin.getRef(), newpin));
        }
    }

    public Map<LegacyPIN, Byte> getPINCounters() throws IOException, EstEIDException {
        select(FID_3F00);
        select(FID_0016);
        HashMap<LegacyPIN, Byte> m = new HashMap<LegacyPIN, Byte>();
        // XXX: Ugly, should parse.
        for (LegacyPIN p : LegacyPIN.values()) {
            m.put(p, read_record(p.getRec())[5]);
        }
        return m;
    }

    public String getPersonalData(PersonalData d) throws IOException, EstEIDException {
        if (currentFID != FID_5044) {
            select(FID_3F00);
            select(FID_EEEE);
            select(FID_5044);
        }
        try {
            return new String(read_record(d.getRec()), "ISO-8859-15").trim();
        } catch (UnsupportedEncodingException e) {
            throw new EstEIDException("Invalid encoding", e);
        }
    }

    // File handling. Returns FCI, if any
    public byte[] select(int fid) throws EstEIDException {
        ResponseAPDU resp = check(transmit(select_apdu(fid, true)));
        currentFID = fid;
        return resp.getData();
    }

    public byte[] read_file(final int bytes) throws EstEIDException {
        byte[] bb = new byte[bytes];
        for (int i = 0; i <= (bytes / chunksize); i++) {
            final int offset = i * chunksize;
            ResponseAPDU r = transmit(new CommandAPDU(0x00, INS_READ_BINARY, offset >> 8, offset & 0xFF, Math.min(chunksize, bytes - offset)));

            // Ignore truncated read
            if (r.getSW() != 0x6282) {
                EstEIDException.check(r);
            }
            System.arraycopy(r.getData(), 0, bb, offset, r.getData().length);
        }
        return bb;
    }

    public byte[] read_record(final byte recno) throws IOException, EstEIDException {
        ResponseAPDU r = transmit(read_record_apdu(recno));
        return check(r).getData();
    }

    public byte[] read_certificate_bytes(int fid) throws EstEIDException {
        select(FID_3F00);
        select(FID_EEEE);
        byte[] fci = select(fid);
        // Get file size from FCI. XXX: hardcoded location
        int size = 0x600;
        if (fci.length >= 13) {
            size = ((fci[11] & 0xFF) << 8) | (fci[12] & 0xFF);
        }
        return read_file(size);
    }

    @Override
    byte[] readCertificate(CERT type) {
        switch (type) {
            case SIGN:
                return read_certificate_bytes(FID_DDCE);
            case AUTH:
                return read_certificate_bytes(FID_AACE);
            default:
                throw new RuntimeException("Invalid enum");
        }
    }

    public String getAppVersion() throws IOException, EstEIDException {
        byte[] v = transmit(new CommandAPDU(0x00, 0xCA, 0x01, 0x00, 0x03)).getData();
        if (v.length == 2) {
            return String.format("%d.%d", v[0], v[1]);
        } else if (v.length == 3) {
            return String.format("%d.%d.%d", v[0], v[1], v[2]);
        } else {
            throw new EstEIDException("Invalid length for EstEID app version: " + v.length);
        }
    }

    // Crypto operations
    void se_restore(int i) throws IOException, EstEIDException {
        check(transmit(new CommandAPDU(0x00, INS_MANAGE_SECURITY_ENVIRONMENT, 0xF3, i)));
    }

    void se_keyref(int type, int ref) throws IOException, EstEIDException {
        check(transmit(new CommandAPDU(0x00, INS_MANAGE_SECURITY_ENVIRONMENT, 0x41, type, new byte[]{(byte) 0x83, 0x03, (byte) 0x80, (byte) (ref >> 8), (byte) ref})));
    }

    @Override
    public byte[] sign(byte[] data, CallbackHandler cb) throws WrongPINException, IOException, UnsupportedCallbackException {

        select(FID_3F00);
        select(FID_EEEE);
        se_restore(1);
        verifyPIN(EstEID.PIN.PIN2, cb);
        CommandAPDU cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1_PSO_SIGN, P2_PSO_SIGN, data, 256);
        return check(transmit(cmd)).getData();

    }

    @Override
    public byte[] authenticate(byte[] data, CallbackHandler cb) throws WrongPINException, IOException, UnsupportedCallbackException {
        select(FID_3F00);
        select(FID_EEEE);
        se_restore(1);
        verifyPIN(EstEID.PIN.PIN1, cb);
        CommandAPDU cmd = new CommandAPDU(0x00, INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, data, 256);
        return check(transmit(cmd)).getData();
    }

    public byte[] decrypt(byte[] data, CallbackHandler cb) throws WrongPINException, IOException, UnsupportedCallbackException {
        select(FID_3F00);
        select(FID_EEEE);
        se_restore(6);
        verifyPIN(PIN.PIN1, cb);
        // Some magic - decryption key reference
        // TODO: discover this from FID 0x0033
        se_keyref(0xB8, 0x1100);
        // prepend 0
        byte[] d = org.bouncycastle.util.Arrays.prepend(data, (byte) 0);

        // The logical limit here is 255
        if (d.length > chunksize) {
            // split in two
            int split = d.length / 2;
            byte[] d1 = Arrays.copyOfRange(d, 0, split);
            byte[] d2 = Arrays.copyOfRange(d, split, d.length);
            // send in two parts with chaining
            CommandAPDU cmd = new CommandAPDU(0x10, INS_PERFORM_SECURITY_OPERATION, P1_PSO_DECRYPT, P2_PSO_DECRYPT, d1, 256);
            check(transmit(cmd));
            cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1_PSO_DECRYPT, P2_PSO_DECRYPT, d2, 256);
            return check(transmit(cmd)).getData();
        } else {
            CommandAPDU cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1_PSO_DECRYPT, P1_PSO_DECRYPT, d, 256);
            return check(transmit(cmd)).getData();
        }

    }

    @Override
    public byte[] dh(ECPublicKey key, CallbackHandler cb) throws WrongPINException, IOException, UnsupportedCallbackException {
        // FIXME: check that point is on curve of cert
        SubjectPublicKeyInfo spk = SubjectPublicKeyInfo.getInstance(key.getEncoded());
        return dh(spk.getPublicKeyData().getBytes(), cb);
    }

    @Override
    public boolean unblockPIN(PIN pin, CallbackHandler cb) throws WrongPINException, IOException, UnsupportedCallbackException {
        return false;
    }

    public byte[] dh(byte[] data, CallbackHandler cb) throws WrongPINException, IOException, UnsupportedCallbackException {
        select(FID_3F00);
        select(FID_EEEE);
        verifyPIN(EstEID.PIN.PIN1, cb);
        data = org.bouncycastle.util.Arrays.concatenate(new byte[]{(byte) 0xA6, 0x66, 0x7F, 0x49, 0x63, (byte) 0x86, 0x61}, data);
        CommandAPDU cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1_PSO_DECRYPT, P2_PSO_DECRYPT, data, 256);
        return check(transmit(cmd)).getData();
    }

    // Transport related
    public APDUBIBO getChannel() {
        return channel;
    }

    @Override
    public void close() {

    }

    // Personal data file records
    public enum PersonalData {
        SURNAME(1),
        GIVEN_NAMES1(2),
        GIVEN_NAMES2(3),
        SEX(4),
        CITIZENSHIP(5),
        DATE_OF_BIRTH(6),
        PERSONAL_ID(7),
        DOCUMENT_NR(8),
        EXPIRY_DATE(9),
        PLACE_OF_BIRTH(10),
        ISSUING_DATE(11),
        PERMIT_TYPE(12),
        REMARK1(13),
        REMARK2(14),
        REMARK3(15),
        REMARK4(16);

        private final int rec;

        PersonalData(int recno) {
            this.rec = recno;
        }

        // Record in file
        public byte getRec() {
            return (byte) rec;
        }
    }

    // PIN codes
    enum LegacyPIN {
        PIN1(1, 1, 3, 12), PIN2(2, 2, 5, 12), PUK(0, 3, 8, 12);

        private final int ref;
        private final int rec;
        private final int min;
        private final int max;


        LegacyPIN(int ref, int rec, int minlen, int maxlen) {
            this.ref = ref;
            this.rec = rec;
            min = minlen;
            max = maxlen;
        }

        // Reference in VERIFY et al
        public byte getRef() {
            return (byte) ref;
        }

        // Record in counter file
        public byte getRec() {
            return (byte) rec;
        }
    }

}
