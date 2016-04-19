/**
 * Copyright (c) 2014-2016 Martin Paljak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.esteid;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import apdu4j.HexUtils;

// Instance of this class keeps state and throws EstEIDException if the response from card is not what it is supposed to be.
// Static methods can be used in a stateless manner.
// Methods throw CardException if card communication fails.
// This class requires some love.
public final class EstEID {

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

		private PersonalData(int recno) {
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


		private PIN(int ref, int rec, int minlen, int maxlen) {
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
	};

	// Shorthands
	public static final PIN PIN1 = PIN.PIN1;
	public static final PIN PIN2 = PIN.PIN2;
	public static final PIN PUK = PIN.PUK;

	// default test card PIN codes from envelope "1" ("00000000001")
	public static final String PIN1String = "0090";
	public static final byte[] testPIN1 = PIN1String.getBytes();
	public static final String PIN2String = "01497";
	public static final byte[] testPIN2 = PIN2String.getBytes();
	public static final String PUKString = "17258403";
	public static final byte[] testPUK = PUKString.getBytes();

	// should be 255 all the time!
	public final static int chunksize = 250;

	// original cold
	public final static ATR micardo_cold_atr = new ATR(HexUtils.hex2bin("3bfe9400ff80b1fa451f034573744549442076657220312e3043"));
	// original warm
	public final static ATR micardo_warm_atr = new ATR(HexUtils.hex2bin("3b6e00ff4573744549442076657220312e30"));
	// 2006 update cold
	public final static ATR micardo_2006_cold_atr = new ATR(HexUtils.hex2bin("3bde18ffc080b1fe451f034573744549442076657220312e302b"));
	// 2006 update warm
	public final static ATR micardo_2006_warm_atr = new ATR(HexUtils.hex2bin("3b5e11ff4573744549442076657220312e30"));
	// DigiID cold. Warm is the same original cold above.
	public final static ATR digiid_cold_atr = new ATR(HexUtils.hex2bin("3b6e00004573744549442076657220312e30"));
	// 2011 cold
	public final static ATR javacard_2011_cold_atr = new ATR(HexUtils.hex2bin("3bfe1800008031fe454573744549442076657220312e30a8"));
	// 2011 warm
	public final static ATR javacard_2011_warm_atr = new ATR(HexUtils.hex2bin("3bfe1800008031fe45803180664090a4162a00830f9000ef"));

	// Card identification
	// AID of modern JavaCard app (FakeEstEID et al) National prefix of Estonia + "EstEID v3.5"
	public static final byte[] aid = new byte[] {(byte)0xD2, (byte)0x33, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x45, (byte)0x73, (byte)0x74, (byte)0x45, (byte)0x49, (byte)0x44, (byte)0x20, (byte)0x76, (byte)0x33, (byte)0x35};

	public static enum CardType {
		MICARDO, DigiID, JavaCard2011, AnyJavaCard
	}

	public static Map<ATR, CardType> knownATRs = new HashMap<ATR, CardType>();
	static {
		knownATRs.put(micardo_cold_atr, CardType.MICARDO);
		knownATRs.put(micardo_warm_atr, CardType.MICARDO);
		knownATRs.put(micardo_2006_cold_atr, CardType.MICARDO);
		knownATRs.put(micardo_2006_warm_atr, CardType.MICARDO);
		knownATRs.put(digiid_cold_atr, CardType.DigiID);
		knownATRs.put(javacard_2011_cold_atr, CardType.JavaCard2011);
		knownATRs.put(javacard_2011_warm_atr, CardType.JavaCard2011);
	}

	// Instance fields
	private CardChannel channel = null;
	private CardType type = null;
	private int currentFID = FID_3F00;

	private EstEID(CardChannel c) {
		channel = c;
	}

	public static EstEID getInstance(CardChannel c) {
		return new EstEID(c);
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

	public static CardType identify(CardTerminal t) throws CardException {
		Card card = t.connect("*");
		card.beginExclusive();
		try {
			ATR atr = card.getATR();
			// Check for ATR.
			if (knownATRs.containsKey(atr)) {
				// DigiID is a broken card
				if (atr.equals(micardo_cold_atr)) {
					// Check if DigiID or Micardo
					ResponseAPDU resp = card.getBasicChannel().transmit(new CommandAPDU(0x00, 0xA4, 0x02, 0x00, new byte[] {0x3F, 0x00}, 256));
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

	public CardType getType() {
		return type;
	}

	// PIN handling
	public static CommandAPDU verify_apdu(PIN pin, String value) {
		return new CommandAPDU(0x00, INS_VERIFY, 0x00, pin.getRef(), value.getBytes());
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
		ResponseAPDU r = change_apdu(pin, oldpin.getBytes(), newpin.getBytes());
		WrongPINException.check(r);
		EstEIDException.check(r);
	}

	public void unblock(PIN pin) throws WrongPINException, CardException, EstEIDException {

		unblock(pin, null);
	}
	public void unblock(PIN pin, String newpin) throws WrongPINException, CardException, EstEIDException {
		ResponseAPDU r = unblock_apdu(pin, newpin.getBytes());
		WrongPINException.check(r);
		EstEIDException.check(r);
	}

	public ResponseAPDU change_apdu(PIN pin, byte[] oldpin, byte[] newpin) throws CardException {
		byte [] v = new byte[oldpin.length + newpin.length];
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
		for (PIN p: PIN.values()) {
			m.put(p, read_record(p.getRec())[5]);
		}
		return m;
	}

	public String getPersonalData(PersonalData d) throws CardException , EstEIDException{
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

	public static CommandAPDU select_apdu(int fid, boolean fci) {
		int p2 = fci ? 0x04 : 0x0C;
		byte [] fidbytes = new byte[2];
		fidbytes[0] = (byte)(fid >> 8);
		fidbytes[1] = (byte)(fid);

		if (fid == FID_3F00) { // Select master file
			return new CommandAPDU(0x00, INS_SELECT, 0x00, p2);
		} else if (fid == FID_EEEE) { // Select DF
			return new CommandAPDU(0x00, INS_SELECT, 0x01, p2, fidbytes);
		} else { // Select EF
			return new CommandAPDU(0x00, INS_SELECT, 0x02, p2, fidbytes);
		}
	}
	// File handling. Returns FCI, if any
	public byte[] select(int fid) throws CardException, EstEIDException {
		ResponseAPDU resp = check(transmit(select_apdu(fid, true)));
		currentFID = fid;
		return resp.getData();
	}
	public byte[] read_file(final int bytes) throws CardException, EstEIDException{
		byte[] bb = new byte[bytes];
		for (int i = 0; i<= (bytes / chunksize); i++) {
			final int offset = i*chunksize;
			ResponseAPDU r = transmit(new CommandAPDU(0x00, INS_READ_BINARY, offset>>8, offset & 0xFF, chunksize));

			// Ignore truncated read
			if (r.getSW() != 0x6282) {
				EstEIDException.check(r);
			}
			System.arraycopy(r.getData(), 0, bb, offset, r.getData().length);
		}
		return bb;
	}

	public static CommandAPDU read_record_apdu(byte recno) {
		return new CommandAPDU(0x00, INS_READ_RECORD, recno, 0x04, 256);
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
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(read_certificate_bytes(fid)));
		} catch (CertificateException e) {
			throw new EstEIDException("Could not parse certificate", e);
		}
	}

	public X509Certificate readAuthCert() throws EstEIDException, CardException {
		return readCertificate(FID_AACE);
	}

	public X509Certificate readSignCert() throws EstEIDException, CardException {
		return readCertificate(FID_DDCE);
	}
	public String getAppVersion() throws CardException, EstEIDException {
		byte [] v = transmit(new CommandAPDU(0x00, 0xCA, 0x01, 0x00, 0x03)).getData();
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
		check(transmit(new CommandAPDU(0x00, INS_MANAGE_SECURITY_ENVIRONMENT, 0x41, type, new byte[] {(byte) 0x83, 0x03, (byte) 0x80, (byte) (ref >> 8), (byte) ref})));
	}

	public byte[] sign(byte[] data, String pin) throws WrongPINException, CardException, EstEIDException {
		select(FID_3F00);
		select(FID_EEEE);
		se_restore(1);
		verify(PIN2, pin);
		CommandAPDU cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1_PSO_SIGN, P2_PSO_SIGN, data, 256);
		return check(transmit(cmd)).getData();
	}

	public byte[] authenticate(byte[] data, String pin) throws WrongPINException, CardException, EstEIDException {
		select(FID_3F00);
		select(FID_EEEE);
		se_restore(1);
		verify(PIN1, pin);
		CommandAPDU cmd = new CommandAPDU(0x00, INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, data, 256);
		return check(transmit(cmd)).getData();
	}

	public byte[] decrypt(byte[] data, String pin) throws WrongPINException, CardException, EstEIDException {
		select(FID_3F00);
		select(FID_EEEE);
		se_restore(6);
		verify(PIN1, pin);
		// Some magic - decryption key reference
		// TODO: discover this from FID 0x0033
		se_keyref(0xB8, 0x1100);
		// prepend 0
		byte[] d = org.bouncycastle.util.Arrays.prepend(data, (byte)0);

		// The logical limit here is 255
		if (d.length > chunksize) {
			// split in two
			int split = d.length/2;
			byte[] d1 = Arrays.copyOfRange(d, 0, split);
			byte[] d2 = Arrays.copyOfRange(d, split, d.length);
			// send in two parts with chaining
			CommandAPDU cmd = new CommandAPDU(0x10, INS_PERFORM_SECURITY_OPERATION, P1_PSO_DECRYPT, P2_PSO_DECRYPT, d1, 256);
			check(transmit(cmd));
			cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1_PSO_DECRYPT, P2_PSO_DECRYPT, d2, 256);
			return check(transmit(cmd)).getData();
		}  else {
			CommandAPDU cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1_PSO_DECRYPT, P1_PSO_DECRYPT, d, 256);
			return check(transmit(cmd)).getData();
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
	private static ResponseAPDU check(ResponseAPDU r) throws EstEIDException {
		return EstEIDException.check(r);
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

	public void crypto_tests(String pin1, String pin2) throws WrongPINException, EstEIDException, CardException {
		Map<PIN, Byte> retries = getPINCounters();
		if (retries.get(PIN1) < 3 || retries.get(PIN2) < 3) {
			throw new IllegalStateException("Will not run crypto tests on a card with not-known or blocked PINs!");
		}
		System.out.println("Testing certificates and crypto ...");

		try {
			// Verify on-card keys vs certificates
			Cipher verify_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			SecureRandom r = SecureRandom.getInstance("SHA1PRNG");
			byte [] rnd = new byte[20];

			// Authentication key
			X509Certificate authcert = readAuthCert();
			System.out.println("Auth cert: " + authcert.getSubjectDN());

			r.nextBytes(rnd);
			verify_cipher.init(Cipher.DECRYPT_MODE, authcert.getPublicKey());
			byte[] result = verify_cipher.doFinal(authenticate(rnd, pin1));
			if (!java.util.Arrays.equals(rnd, result)) {
				throw new EstEIDException("Card and auth key don't match!");
			} else {
				System.out.println("ENCRYPT: OK");
			}

			r.nextBytes(rnd);
			verify_cipher.init(Cipher.ENCRYPT_MODE, authcert.getPublicKey());
			result = verify_cipher.doFinal(rnd);
			if (!java.util.Arrays.equals(rnd, decrypt(result, pin1))) {
				throw new EstEIDException("Card and auth key don't match on decryption!");
			} else {
				System.out.println("DECRYPT: OK");
			}

			// Signature key
			X509Certificate signcert = readSignCert();
			System.out.println("Sign cert: " + signcert.getSubjectDN());

			r.nextBytes(rnd);
			verify_cipher.init(Cipher.DECRYPT_MODE, signcert.getPublicKey());
			result = verify_cipher.doFinal(sign(rnd, pin2));
			if (!java.util.Arrays.equals(rnd, result)) {
				throw new EstEIDException("Card and sign key don't match!");
			} else {
				System.out.println("ENCRYPT: OK");
			}
		} catch (GeneralSecurityException e) {
			System.out.println("FAILURE");
		}
	}

	public static String hex2numbers(String s) {
		return s.toUpperCase().replace('A', '0').replace('B', '1').replace('C', '2').replace('D', '3').replace('E', '4').replace('F', '5');
	}

	static String make_random_pin(int len) {
		try {
			return hex2numbers(new BigInteger(len*8, SecureRandom.getInstance("SHA1PRNG")).toString(16)).substring(0, len);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Bad environment", e);
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
		for (PIN p: Arrays.asList(PIN1, PIN2)) {
			for (int i = 0; i<3; i++) {
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

	public static String getVersion() {
		String version = "unknown-development";
		try (InputStream versionfile = EstEID.class.getResourceAsStream("version.txt")) {
			if (versionfile != null) {
				try (BufferedReader vinfo = new BufferedReader(new InputStreamReader(versionfile))) {
					version = vinfo.readLine();
				}
			}
		} catch (IOException e) {
			version = "unknown-error";
		}
		return version;
	}
}
