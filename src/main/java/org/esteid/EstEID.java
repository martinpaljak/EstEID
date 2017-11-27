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

import apdu4j.HexUtils;
import apdu4j.LoggingCardTerminal;
import apdu4j.SCard;
import apdu4j.TerminalManager;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.esteid.sk.CertificateHelpers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.smartcardio.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

// Instance of this class keeps state and throws EstEIDException if the response from card is not what it is supposed to be.
// Static methods can be used in a stateless manner.
// Methods throw CardException if card communication fails.
// This class requires some love.
public final class EstEID implements AutoCloseable {

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
    public static final PIN PIN1 = PIN.PIN1;
    public static final PIN PIN2 = PIN.PIN2;
    public static final PIN PUK = PIN.PUK;
    // default test card PIN codes from envelope "1" ("00000000001")
    public static final String PIN1String = "0090";
    public static final String PIN2String = "01497";
    public static final String PUKString = "17258403";
    // should be 255 all the time!
    public final static int chunksize = 250;
    public static final String AID = "D23300000045737445494420763335";
    public static final Map<ATR, CardType> knownATRs;
    private static final Logger log = LoggerFactory.getLogger(EstEID.class);
    // AID of modern JavaCard app (FakeEstEID et al) National prefix of Estonia + "EstEID v3.5"
    private static final byte[] aid = HexUtils.hex2bin(AID);

    private static final SecureRandom rnd;

    static {
        Map<ATR, CardType> atrs = new HashMap<>();
        atrs.put(new ATR(HexUtils.hex2bin("3bfe9400ff80b1fa451f034573744549442076657220312e3043")), CardType.MICARDO);
        atrs.put(new ATR(HexUtils.hex2bin("3b6e00ff4573744549442076657220312e30")), CardType.MICARDO);
        atrs.put(new ATR(HexUtils.hex2bin("3bde18ffc080b1fe451f034573744549442076657220312e302b")), CardType.MICARDO);
        atrs.put(new ATR(HexUtils.hex2bin("3b5e11ff4573744549442076657220312e30")), CardType.MICARDO);
        atrs.put(new ATR(HexUtils.hex2bin("3b6e00004573744549442076657220312e30")), CardType.DigiID);
        atrs.put(new ATR(HexUtils.hex2bin("3bfe1800008031fe454573744549442076657220312e30a8")), CardType.JavaCard2011);
        atrs.put(new ATR(HexUtils.hex2bin("3bfe1800008031fe45803180664090a4162a00830f9000ef")), CardType.JavaCard2011);
        atrs.put(new ATR(HexUtils.hex2bin("3BFA1800008031FE45FE654944202F20504B4903")), CardType.JavaCard2011); // Digi-ID 2017 ECC upgrade
        knownATRs = Collections.unmodifiableMap(atrs);
        rnd = new SecureRandom();
        rnd.nextBytes(new byte[2]); // Seed and drop
    }

    private boolean debug = false;
    private X509Certificate authCert;
    private X509Certificate signCert;
    private Card card = null;
    // Instance fields
    private CardChannel channel = null;
    private CardType type = null;
    private int currentFID = FID_3F00;

    private EstEID(CardChannel c) {
        channel = c;
    }

    private EstEID(Card card) {
        this(card.getBasicChannel());
        this.card = card;
    }

    public static EstEID getInstance(CardChannel c) {
        return new EstEID(c);
    }


    /**
     * Locates a CardTerminal that contains an EstEID card, based on ATR
     * If there are multiple terminals, asks user for a choise (assumes Console)
     *
     * @return the CardTerminal that contains an EstEID card or null, if such terminal does not exist
     * @throws CardException if
     */
    public static CardTerminal getTerminal() throws CardException {
        final List<CardTerminal> terms;
        try {
            terms = TerminalManager.byATR(knownATRs.keySet());
        } catch (NoSuchAlgorithmException e) {
            return null;
            //throw new CardNotPresentException("PC/SC not available", e);
        }
        if (terms.size() == 0)
            return null;
        if (terms.size() == 1)
            return terms.get(0);

        throw new IllegalStateException("Currently only one terminal is supported");

//        System.out.println("Choose reader: ");
//        int i = 0;
//        for (CardTerminal t : terms) {
//            Card c = null;
//            try {
//                c = t.connect("*");
//                System.out.println(i + ". " + t.getName() + ": " + identify(c));
//            } catch (CardException | EstEIDException e) {
//                // Ignore at this time
//            } finally {
//                if (c != null)
//                    c.disconnect(false);
//            }
//            i++;
//        }
//        // TODO: select
//        return terms.get(0);
    }


    public static EstEID locateOneOf(Collection<X509Certificate> certs) throws CardException, NoSuchAlgorithmException, EstEIDException {
        return locateOneOf(certs, false);
    }

    public static EstEID locateOneOf(Collection<X509Certificate> certs, boolean debug) throws CardException, NoSuchAlgorithmException, EstEIDException {
        final List<CardTerminal> terms = TerminalManager.byATR(knownATRs.keySet());
        for (CardTerminal t : terms) {
            if (debug)
                t = LoggingCardTerminal.getInstance(t);
            final Card c;
            try {
                c = t.connect("*");
            } catch (CardException e) {
                if (TerminalManager.getExceptionMessage(e).equals(SCard.SCARD_E_SHARING_VIOLATION)) {
                    // exclusive, ignore
                    continue;
                }
                throw e;
            }
            EstEID e = new EstEID(c);

            X509Certificate a = e.readAuthCert();
            for (X509Certificate x : certs) {
                if (x.equals(a))
                    return e;
            }

            X509Certificate s = e.readSignCert();
            for (X509Certificate x : certs) {
                if (x.equals(s))
                    return e;
            }
            c.disconnect(false);
        }
        return null;
    }

    public static EstEID anyCard() throws CardException, CertificateParsingException, NoSuchAlgorithmException, EstEIDException {
        return anyCard(false);
    }

    public static EstEID anyCard(boolean debug) throws CardException, CertificateParsingException, NoSuchAlgorithmException, EstEIDException {
        ArrayList<AutoCloseable> toClose = new ArrayList<>();
        ArrayList<EstEID> selection = new ArrayList<>();
        final List<CardTerminal> terms = TerminalManager.byATR(knownATRs.keySet());
        try {
            for (CardTerminal t : terms) {
                if (debug)
                    t = LoggingCardTerminal.getInstance(t);
                final Card c;
                try {
                    c = t.connect("*");
                } catch (CardException e) {
                    if (TerminalManager.getExceptionMessage(e).equals(SCard.SCARD_E_SHARING_VIOLATION)) {
                        // exclusive, ignore this reader
                        continue;
                    }
                    throw e;
                }
                EstEID e = new EstEID(c);
                selection.add(e);
            }

            if (selection.size() == 0)
                return null;

            if (selection.size() > 1) {
                for (EstEID e : selection) {
                    X509Certificate x = e.readAuthCert();
                    System.out.println(selection.indexOf(e) + ": " + e);
                }
                // FIXME: UX robustness
                Console console = System.console();
                if (console == null) {
                    throw new IllegalStateException("Need access to console");
                }
                String choice = console.readLine("Enter your selection: ");
                int i = Integer.parseInt(choice);
                if (i < 0 || i > selection.size())
                    throw new IllegalStateException("Bad selection: " + i);
                return selection.get(Integer.parseInt(choice));
            } else {
                return selection.get(0);
            }
        } finally {
            for (AutoCloseable a : toClose) {
                try {
                    a.close();
                } catch (Exception e) {
                    log.warn("Failed to close: {}", e.getMessage(), e);
                }
            }
        }
    }


    public static EstEID start(CardChannel c) throws CardException, EstEIDException {
        // FIXME: Try to select AID first
        ResponseAPDU resp = c.transmit(select_apdu(FID_3F00, false));
        if (resp.getSW() == 0x6A83 || resp.getSW() == 0x6D00) {
            EstEIDException.check(resp, "Locked up Digi-ID detected, must reset card before use");
        }
        EstEIDException.check(resp);
        return getInstance(c);
    }

    public static String identify(Card c) throws CardException, EstEIDException {
        EstEID e = EstEID.getInstance(c.getBasicChannel());
        return e.getPersonalData(PersonalData.GIVEN_NAMES1) + "," + e.getPersonalData(PersonalData.SURNAME) + "," + e.getPersonalData(PersonalData.PERSONAL_ID);
    }

    public static CardType identify(CardTerminal t) throws CardException {
        Card card = t.connect("*");
        card.beginExclusive();
        try {
            ATR atr = card.getATR();
            // Check for ATR.
            if (knownATRs.containsKey(atr)) {
                // DigiID is a broken card (fixed to Micardo cold ATR)
                if (Arrays.equals(atr.getBytes(), HexUtils.hex2bin("3bfe9400ff80b1fa451f034573744549442076657220312e3043"))) {
                    // Check if DigiID or Micardo
                    ResponseAPDU resp = card.getBasicChannel().transmit(new CommandAPDU(0x00, 0xA4, 0x02, 0x00, new byte[]{0x3F, 0x00}, 256));
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
                return knownATRs.get(atr);
            }

            // Check for generic modern Applet if ATR is unknown
            ResponseAPDU resp = card.getBasicChannel().transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid));
            if (resp.getSW() == 0x9000) {
                return CardType.AnyJavaCard;
            }
        } finally {
            card.endExclusive();
        }
        // If we get here this is not our card.
        return null;
    }

    // PIN handling
    public static CommandAPDU verify_apdu(PIN pin, String value) {
        return new CommandAPDU(0x00, INS_VERIFY, 0x00, pin.getRef(), value.getBytes(StandardCharsets.US_ASCII));
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

    private static ResponseAPDU check(ResponseAPDU r) throws EstEIDException {
        return EstEIDException.check(r);
    }

    static String make_random_pin(int len) {
        return Legacy.hex2numbers(new BigInteger(len * 8, rnd).toString(16)).substring(0, len);
    }

    public static String getVersion() {
        String version = "unknown-development";
        try (InputStream versionfile = EstEID.class.getResourceAsStream("pro_version.txt")) {
            if (versionfile != null) {
                try (BufferedReader vinfo = new BufferedReader(new InputStreamReader(versionfile, "UTF-8"))) {
                    version = vinfo.readLine();
                }
            }
        } catch (IOException e) {
            version = "unknown-error";
        }
        return version;
    }

    public static byte[] rs2der(byte[] c) {
        try {
            byte[] r = Arrays.copyOfRange(c, 0, c.length / 2);
            byte[] s = Arrays.copyOfRange(c, c.length / 2, c.length);
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            DEROutputStream ders = new DEROutputStream(bo);
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(new BigInteger(1, r)));
            v.add(new ASN1Integer(new BigInteger(1, s)));
            ders.writeObject(new DERSequence(v));
            return bo.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Can not convert");
        }
    }

    public CardType getType() {
        return type;
    }

    public ResponseAPDU verify_cmd(PIN pin, String value) throws CardException, WrongPINException, EstEIDException {
        if (value.length() < pin.min || value.length() > pin.max)
            throw new IllegalArgumentException("PIN has incorrect length: " + value.length());
        ResponseAPDU r = transmit(verify_apdu(pin, value));
        WrongPINException.check(r);
        return EstEIDException.check(r);
    }

    public void verify(PIN pin, String value) throws WrongPINException, CardException, EstEIDException {
        verify_cmd(pin, value);
    }

    public void change(PIN pin, String oldpin, String newpin) throws WrongPINException, CardException, EstEIDException {
        ResponseAPDU r = change_apdu(pin, oldpin.getBytes(StandardCharsets.US_ASCII), newpin.getBytes(StandardCharsets.US_ASCII));
        WrongPINException.check(r);
        EstEIDException.check(r);
    }

    public void unblock(PIN pin) throws WrongPINException, CardException, EstEIDException {
        unblock(pin, null);
    }

    public void unblock(PIN pin, String newpin) throws WrongPINException, CardException, EstEIDException {
        ResponseAPDU r = unblock_apdu(pin, newpin == null ? null : newpin.getBytes(StandardCharsets.US_ASCII));
        WrongPINException.check(r);
        EstEIDException.check(r);
    }

    public ResponseAPDU change_apdu(PIN pin, byte[] oldpin, byte[] newpin) throws CardException {
        byte[] v = new byte[oldpin.length + newpin.length];
        System.arraycopy(oldpin, 0, v, 0, oldpin.length);
        System.arraycopy(newpin, 0, v, oldpin.length, newpin.length);
        return transmit(new CommandAPDU(0x00, INS_CHANGE_REFERENCE_DATA, 0x00, pin.getRef(), v));
    }

    public ResponseAPDU unblock_apdu(PIN pin, byte[] newpin) throws CardException {
        if (newpin == null) {
            return transmit(new CommandAPDU(0x00, INS_RESET_RETRY_COUNTER, 0x03, pin.getRef()));
        } else {
            return transmit(new CommandAPDU(0x00, INS_RESET_RETRY_COUNTER, 0x00, pin.getRef(), newpin));
        }
    }

    public Map<PIN, Byte> getPINCounters() throws CardException, EstEIDException {
        select(FID_3F00);
        select(FID_0016);
        HashMap<PIN, Byte> m = new HashMap<PIN, Byte>();
        // XXX: Ugly, should parse.
        for (PIN p : PIN.values()) {
            m.put(p, read_record(p.getRec())[5]);
        }
        return m;
    }

    public String getPersonalData(PersonalData d) throws CardException, EstEIDException {
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
    public byte[] select(int fid) throws CardException, EstEIDException {
        ResponseAPDU resp = check(transmit(select_apdu(fid, true)));
        currentFID = fid;
        return resp.getData();
    }

    public byte[] read_file(final int bytes) throws CardException, EstEIDException {
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

    public byte[] read_record(final byte recno) throws CardException, EstEIDException {
        ResponseAPDU r = transmit(read_record_apdu(recno));
        return check(r).getData();
    }

    public byte[] read_certificate_bytes(int fid) throws CardException, EstEIDException {
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

    private X509Certificate readCertificate(int fid) throws CardException, EstEIDException {
        try {
            if (card != null)
                card.beginExclusive();
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(read_certificate_bytes(fid)));
        } catch (CertificateException e) {
            throw new EstEIDException("Could not parse certificate", e);
        } finally {
            if (card != null)
                card.endExclusive();
        }
    }

    public X509Certificate getAuthCert() throws CardException, EstEIDException {
        if (authCert == null)
            authCert = readAuthCert();
        return authCert;
    }

    public X509Certificate getSignCert() throws CardException, EstEIDException {
        if (signCert == null)
            signCert = readSignCert();
        return signCert;
    }

    public X509Certificate readAuthCert() throws EstEIDException, CardException {
        return readCertificate(FID_AACE);
    }

    public X509Certificate readSignCert() throws EstEIDException, CardException {
        return readCertificate(FID_DDCE);
    }

    public String getAppVersion() throws CardException, EstEIDException {
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
    public void se_restore(int i) throws CardException, EstEIDException {
        check(transmit(new CommandAPDU(0x00, INS_MANAGE_SECURITY_ENVIRONMENT, 0xF3, i)));
    }

    public void se_keyref(int type, int ref) throws CardException, EstEIDException {
        check(transmit(new CommandAPDU(0x00, INS_MANAGE_SECURITY_ENVIRONMENT, 0x41, type, new byte[]{(byte) 0x83, 0x03, (byte) 0x80, (byte) (ref >> 8), (byte) ref})));
    }

    public byte[] sign(byte[] data, String pin) throws WrongPINException, CardException, EstEIDException {
        try {
            if (card != null)
                card.beginExclusive();
            select(FID_3F00);
            select(FID_EEEE);
            se_restore(1);
            verify(PIN2, pin);
            CommandAPDU cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1_PSO_SIGN, P2_PSO_SIGN, data, 256);
            return check(transmit(cmd)).getData();
        } finally {
            if (card != null)
                card.endExclusive();
        }
    }

    public byte[] authenticate(byte[] data, String pin) throws WrongPINException, CardException, EstEIDException {
        try {
            if (card != null)
                card.beginExclusive();
            select(FID_3F00);
            select(FID_EEEE);
            se_restore(1);
            verify(PIN1, pin);
            CommandAPDU cmd = new CommandAPDU(0x00, INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, data, 256);
            return check(transmit(cmd)).getData();
        } finally {
            if (card != null)
                card.endExclusive();
        }
    }

    public byte[] decrypt(byte[] data, String pin) throws WrongPINException, CardException, EstEIDException {
        try {
            if (card != null)
                card.beginExclusive();
            select(FID_3F00);
            select(FID_EEEE);
            se_restore(6);
            verify(PIN1, pin);
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
        } finally {
            if (card != null)
                card.endExclusive();
        }
    }

    public byte[] dh(ECPublicKey key, String pin) throws WrongPINException, CardException, EstEIDException {
        // FIXME: check that point is on curve of cert
        SubjectPublicKeyInfo spk = SubjectPublicKeyInfo.getInstance(key.getEncoded());
        return dh(spk.getPublicKeyData().getBytes(), pin);
    }

    public byte[] dh(byte[] data, String pin) throws WrongPINException, CardException, EstEIDException {
        try {
            if (card != null)
                card.beginExclusive();
            select(FID_3F00);
            select(FID_EEEE);
            verify(PIN1, pin);
            data = org.bouncycastle.util.Arrays.concatenate(new byte[]{(byte) 0xA6, 0x66, 0x7F, 0x49, 0x63, (byte) 0x86, 0x61}, data);
            CommandAPDU cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1_PSO_DECRYPT, P2_PSO_DECRYPT, data, 256);
            return check(transmit(cmd)).getData();
        } finally {
            if (card != null)
                card.endExclusive();
        }
    }

    // Transport related
    public CardChannel getChannel() {
        return channel;
    }

    public ResponseAPDU transmit(CommandAPDU cmd) throws CardException {
        return channel.transmit(cmd);
    }

    public ResponseAPDU check(CommandAPDU cmd) throws EstEIDException, CardException {
        return EstEIDException.check(transmit(cmd));
    }

    public void crypto_tests(String pin1, String pin2) throws WrongPINException, EstEIDException, CardException {
        Map<PIN, Byte> retries = getPINCounters();
        if (retries.get(PIN1) < 3 || retries.get(PIN2) < 3) {
            throw new IllegalStateException("Will not run crypto tests on a card with not-known or blocked PINs!");
        }
        System.out.println("Testing certificates and crypto ...");

        try {
            if (card != null)
                card.beginExclusive();
            // Authentication key
            X509Certificate authcert = readAuthCert();
            System.out.println("Auth cert: " + authcert.getSubjectDN());

            if (authcert.getPublicKey().getAlgorithm().equals("EC")) {
                Signature v = Signature.getInstance("NONEwithECDSA", "BC");
                byte[] hash = new byte[0x30];
                rnd.nextBytes(hash);

                v.initVerify(authcert.getPublicKey());
                v.update(hash);
                if (!v.verify(rs2der(authenticate(hash, pin1)))) {
                    throw new EstEIDException("Card and auth key don't match on authentication!");
                } else {
                    System.out.println("AUTHENTICATE: OK");
                }

                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                generator.initialize(new ECGenParameterSpec("secp384r1"));
                KeyPair ephemeral = generator.generateKeyPair();

                ka.init(ephemeral.getPrivate());
                ka.doPhase(authcert.getPublicKey(), true);
                byte[] host_secret = ka.generateSecret();
                byte[] card_secret = dh((ECPublicKey) ephemeral.getPublic(), pin1);

                if (!java.util.Arrays.equals(card_secret, host_secret)) {
                    throw new EstEIDException("Card and auth key don't match!");
                } else {
                    System.out.println("KEY AGREEMENT: OK");
                }
            } else if (authcert.getPublicKey().getAlgorithm().equals("RSA")) {
                // Verify on-card keys vs certificates
                Cipher verify_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                byte[] hash = new byte[20];

                rnd.nextBytes(hash);
                verify_cipher.init(Cipher.DECRYPT_MODE, authcert.getPublicKey());
                byte[] result = verify_cipher.doFinal(authenticate(hash, pin1));
                if (!java.util.Arrays.equals(hash, result)) {
                    throw new EstEIDException("Card and auth key don't match!");
                } else {
                    System.out.println("ENCRYPT: OK");
                }

                rnd.nextBytes(hash);
                verify_cipher.init(Cipher.ENCRYPT_MODE, authcert.getPublicKey());
                result = verify_cipher.doFinal(hash);
                if (!java.util.Arrays.equals(hash, decrypt(result, pin1))) {
                    throw new EstEIDException("Card and auth key don't match on decryption!");
                } else {
                    System.out.println("DECRYPT: OK");
                }
            }

            // Signature key
            X509Certificate signcert = readSignCert();
            System.out.println("Sign cert: " + signcert.getSubjectDN());

            if (signcert.getPublicKey().getAlgorithm().equals("EC")) {
                Signature v = Signature.getInstance("NONEwithECDSA", "BC");
                byte[] hash = new byte[0x30];
                rnd.nextBytes(hash);
                v.initVerify(signcert.getPublicKey());
                v.update(hash);
                if (!v.verify(rs2der(sign(hash, pin2)))) {
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
                byte[] result = verify_cipher.doFinal(sign(hash, pin2));
                if (!java.util.Arrays.equals(hash, result)) {
                    throw new EstEIDException("Card and sign key don't match on signing!");
                } else {
                    System.out.println("SIGN: OK");
                }
            }
        } catch (GeneralSecurityException e) {
            System.out.println("FAILURE");
        } finally {
            if (card != null)
                card.endExclusive();
        }
    }

    public void pin_tests(String pin1, String pin2, String puk) throws CardException, WrongPINException, EstEIDException {

        Map<PIN, Byte> retries = getPINCounters();
        if (retries.get(PIN1) < 3 || retries.get(PIN2) < 3 || retries.get(PUK) < 3) {
            throw new IllegalStateException("Will not run pin tests on a card with not-known or blocked PINs!");
        }
        System.out.println("Testing PIN codes ...");
        String newpin1 = make_random_pin(4);
        String newpin2 = make_random_pin(5);
        String newpuk = make_random_pin(8);

        // Verify all PIN-s
        verify(PIN1, pin1);
        verify(PIN2, pin2);
        verify(PUK, puk);
        System.out.println("VERIFY: OK");

        // Change all pins to new and back
        change(PIN1, pin1, newpin1);
        change(PIN1, newpin1, pin1);

        change(PIN2, pin2, newpin2);
        change(PIN2, newpin2, pin2);

        change(PUK, puk, newpuk);
        change(PUK, newpuk, puk);
        System.out.println("CHANGE: OK");

        // Block pin1 and pin2 and unblock with PUK
        for (PIN p : Arrays.asList(PIN1, PIN2)) {
            for (int i = 0; i < 3; i++) {
                try {
                    verify(p, make_random_pin(p.max));
                } catch (WrongPINException e) {
                    System.out.println("Expected exception: " + e.toString());
                }
            }
        }

        // Verify PUK and unblock PIN2
        verify(PUK, puk);
        unblock(PIN1);
        // Unblock PIN2
        verify(PUK, puk);
        unblock(PIN2);
        System.out.println("UNBLOCK: OK");
    }

    @Override
    public void close() {
        if (card != null) {
            try {
                card.disconnect(false);
            } catch (CardException e) {
                log.warn("Could not disconnect: {} ", e.getMessage(), e);
            }
        }
    }

    @Override
    public String toString() {
        try {
            X509Certificate a = getAuthCert();
            return CertificateHelpers.getCN(a) + " (" + a.getPublicKey().getAlgorithm() + ")";
        } catch (CardException | EstEIDException | CertificateParsingException e) {
            return "[Errored EstEID: " + e.getMessage() + "]";
        }
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
    public enum PIN {
        PIN1(1, 1, 3, 12), PIN2(2, 2, 5, 12), PUK(0, 3, 8, 12);

        private final int ref;
        private final int rec;
        private final int min;
        private final int max;


        PIN(int ref, int rec, int minlen, int maxlen) {
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

    public enum CardType {
        MICARDO, DigiID, JavaCard2011, AnyJavaCard;
    }

    // Exceptions
    @SuppressWarnings("serial")
    public static class EstEIDException extends Exception {
        private EstEIDException(int sw, String message) {
            super(message + ": 0x" + Integer.toHexString(sw).toUpperCase());
        }

        public EstEIDException(String msg) {
            super(msg);
        }

        public EstEIDException(String msg, Throwable reason) {
            super(msg, reason);
        }

        public static ResponseAPDU check(ResponseAPDU r) throws EstEIDException {
            return check(r, "Unexpected response");
        }

        public static ResponseAPDU check(ResponseAPDU r, String message) throws EstEIDException {
            if (r.getSW() != 0x9000) {
                throw new EstEIDException(r.getSW(), message);
            }
            return r;
        }
    }

    @SuppressWarnings("serial")
    public static class WrongPINException extends Exception {
        private String status;
        private byte remaining;

        private WrongPINException(byte remaining, String status) {
            this.remaining = remaining;
            this.status = status;
        }

        public static ResponseAPDU check(ResponseAPDU r) throws WrongPINException {
            check(r.getSW());
            return r;
        }

        public static void check(int sw) throws WrongPINException {
            if ((sw & 0x6300) == 0x6300) {
                throw new WrongPINException((byte) (sw & 0xF), "");
            } else if (sw == 0x6983) { // FIXME symbol
                throw new WrongPINException((byte) 0, " (blocked)");
            }
        }

        public byte getRemaining() {
            return remaining;
        }

        @Override
        public String toString() {
            return "Wrong PIN: " + remaining + " tries remaining" + status;
        }
    }
}
