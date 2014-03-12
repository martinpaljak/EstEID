/**
 * Copyright (c) 2014 Martin Paljak
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
package esteidhacker;

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import openkms.gp.GPUtils;
import openkms.gp.TerminalManager;

import org.bouncycastle.crypto.RuntimeCryptoException;

public final class EstEID {

	// Various constants
	// Commands
	public static int INS_SELECT = 0xA4;
	public static int INS_READ_BINARY = 0xB0;
	public static int INS_READ_RECORD = 0xB2;

	public static int INS_VERIFY = 0x20;
	public static int INS_CHANGE_REFERENCE_DATA = 0x24;
	public static int INS_RESET_RETRY_COUNTER = 0x2C;

	public static int INS_MANAGE_SECURITY_ENVIRONMENT = 0x22;
	public static int INS_PERFORM_SECURITY_OPERATION = 0x2A;
	public static int INS_INTERNAL_AUTHENTICATE = 0x88;

	public static int P1P2_PSO_SIGN = 0x9E9A;
	public static int P1P2_PSO_DECRYPT = 0x8086;


	// File identifiers
	private final static int FID_3F00 = 0x3F00;
	private final static int FID_0013 = 0x0013;
	private final static int FID_0016 = 0x0016;
	private final static int FID_EEEE = 0xEEEE;
	private final static int FID_5044 = 0x5044;
	private final static int FID_AACE = 0xAACE;
	private final static int FID_DDCE = 0xDDCE;
	private final static int FID_0033 = 0x0033;

	// PIN codes
	public enum PIN {
		PIN1(1), PIN2(2), PUK(0);

		private final int ref;

		private PIN(int ref) {
			this.ref = ref;
		}
		public int getRef() {
			return ref;
		}
	};
	// Shorthands
	public static final PIN PIN1 = PIN.PIN1;
	public static final PIN PIN2 = PIN.PIN2;
	public static final PIN PUK = PIN.PUK;

	// default test card PIN codes.
	public static final String PIN1String = "0090";
	public static final byte[] testPIN1 = PIN1String.getBytes();
	public static final String PIN2String = "01497";
	public static final byte[] testPIN2 = PIN2String.getBytes();
	public static final String PUKString = "17258403";
	public static final byte[] testPUK = PUKString.getBytes();

	// AID of modern JavaCard
	public static final byte[] aid = new byte[] {(byte)0xD2, (byte)0x33, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x45, (byte)0x73, (byte)0x74, (byte)0x45, (byte)0x49, (byte)0x44, (byte)0x20, (byte)0x76, (byte)0x33, (byte)0x35};

	// should be 255 all the time!
	public final static int chunksize = 250;
	public static enum CardType {
		MICARDO, DigiID, JavaCard2011, AnyJavaCard
	}

	public static Map<ATR, CardType> knownATRs = new HashMap<ATR, CardType>();
	static {
		// original cold
		knownATRs.put(new ATR(GPUtils.stringToByteArray("3bfe9400ff80b1fa451f034573744549442076657220312e3043")), CardType.MICARDO);
		// original warm
		knownATRs.put(new ATR(GPUtils.stringToByteArray("3b6e00ff4573744549442076657220312e30")), CardType.MICARDO);
		// 2006 update cold
		knownATRs.put(new ATR(GPUtils.stringToByteArray("3bde18ffc080b1fe451f034573744549442076657220312e302b")), CardType.MICARDO);
		// 2006 update warm
		knownATRs.put(new ATR(GPUtils.stringToByteArray("3b5e11ff4573744549442076657220312e30")), CardType.MICARDO);
		// DigiID cold. Warm is the same as above.
		knownATRs.put(new ATR(GPUtils.stringToByteArray("3b6e00004573744549442076657220312e30")), CardType.DigiID);
		// 2011 cold
		knownATRs.put(new ATR(GPUtils.stringToByteArray("3bfe1800008031fe454573744549442076657220312e30a8")), CardType.JavaCard2011);
	}

	// Instance fields
	private X509Certificate auth = null;
	private X509Certificate sign = null;

	private Card card;
	private final CardTerminal terminal;
	private CardType type = null;


	private EstEID(CardTerminal t) {
		terminal = t;
	}

	public static EstEID getInstance(CardTerminal t) throws CardException {
		EstEID eid = new EstEID(t);
		eid.identify();
		return eid;
	}

	private void identify() throws CardException {
		card = terminal.connect("*");
		ATR atr = card.getATR();
		if (knownATRs.containsKey(atr)) {
			// FIXME: refactor. atr mnemonics
			if (atr.equals(new ATR(GPUtils.stringToByteArray("3bfe9400ff80b1fa451f034573744549442076657220312e3043")))) {
				// Check if DigiID or Micardo
				ResponseAPDU resp = transmit(new CommandAPDU(0x00, 0xA4, 0x02, 0x00, new byte[] {0x3F, 0x00}, 256));
				if (resp.getSW() == 0x9000) {
					// This also selected MF
					type = CardType.DigiID;
					return;
				}
				if (resp.getSW() == 0x6A83) {
					// Locked up DigiID, reset card
					TerminalManager.disconnect(card, true);
					card = terminal.connect("*");
					type = CardType.DigiID;
					return;
				}
			}
			type = knownATRs.get(atr);
		}

		// Check for generic Applets if ATR is unknown
		ResponseAPDU resp = transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid));
		if (resp.getSW() == 0x9000) {
			type = CardType.AnyJavaCard;
		}
	}

	public CardType getType() {
		return type;
	}
	public Card getCard() {
		return card;
	}

	// PIN handling
	public void verify(PIN pin, String value) throws WrongPINException, CardException {
		try {
			verify(pin, value.getBytes());
		} catch (EstEIDException e) {
			if (e.getSW() == 0x6983 || ((e.getSW() & 0x6300) == 0x6300)) {
				throw new WrongPINException(e.getSW());
			}
		}
	}

	public void change(PIN pin, String oldpin, String newpin) throws WrongPINException, CardException {
		try {
			change(pin, oldpin.getBytes(), newpin.getBytes());
		} catch (EstEIDException e) {
			if (e.getSW() == 0x6983 || ((e.getSW() & 0x6300) == 0x6300)) {
				throw new WrongPINException(e.getSW());
			}
		}
	}

	public void unblock(PIN pin, String newpin) throws WrongPINException, CardException {
		try {
			unblock(pin, newpin.getBytes());
		} catch (EstEIDException e) {
			if (e.getSW() == 0x6983 || ((e.getSW() & 0x6300) == 0x6300)) {
				throw new WrongPINException(e.getSW());
			}
		}
	}

	public ResponseAPDU verify(PIN pin, byte[] value) throws CardException {
		return check(transmit(new CommandAPDU(0x00, INS_VERIFY, 0x00, pin.getRef(), value)));
	}

	public ResponseAPDU change(PIN pin, byte[] oldpin, byte[] newpin) throws CardException {
		byte [] v = new byte[oldpin.length + newpin.length];
		System.arraycopy(oldpin, 0, v, 0, oldpin.length);
		System.arraycopy(newpin, 0, v, oldpin.length, newpin.length);
		return check(transmit(new CommandAPDU(0x00, INS_CHANGE_REFERENCE_DATA, pin.getRef(), 0x00, v)));
	}

	public ResponseAPDU unblock(PIN pin, byte[] newpin) throws CardException {
		if (newpin == null) {
			return check(transmit(new CommandAPDU(0x00, INS_RESET_RETRY_COUNTER, 0x00, pin.getRef(), newpin)));
		} else {
			return check(transmit(new CommandAPDU(0x00, INS_RESET_RETRY_COUNTER, 0x03, pin.getRef())));
		}
	}

	// File handling
	public void select(int fid) throws CardException {
		byte [] fidbytes = new byte[2];
		fidbytes[0] = (byte)(fid >> 8);
		fidbytes[1] = (byte)(fid);

		if (fid == FID_3F00) { // Select master file
			check(transmit(new CommandAPDU(0x00, INS_SELECT, 0x00, 0x0C)));
		} else if (fid == FID_EEEE) { // Select DF
			check(transmit(new CommandAPDU(0x00, INS_SELECT, 0x01, 0x0C, fidbytes)));
		} else { // Select EF
			check(transmit(new CommandAPDU(0x00, INS_SELECT, 0x02, 0x0C, fidbytes)));
		}
	}

	public byte[] read(final int bytes) throws CardException {
		byte[] bb = new byte[bytes];
		for (int i = 0; i<= (bytes / chunksize); i++) {
			final int offset = i*chunksize;
			ResponseAPDU r = transmit(new CommandAPDU(0x00, INS_READ_BINARY, offset>>8, offset & 0xFF, 256));
			try {
				check(r);
			} catch (EstEIDException e) {
				// DigiID truncates on Le==0x00
				if (e.getSW() == 0x6282 && type != CardType.DigiID) {
					throw e;
				}
			}
			System.arraycopy(r.getData(), 0, bb, offset, r.getData().length);
		}
		return bb;
	}


	private X509Certificate readCertificate(int fid) throws EstEIDException, CardException {
		select(FID_3F00);
		select(FID_EEEE);
		select(fid);

		try {
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(read(0x600)));
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	public X509Certificate readAuthCert() throws EstEIDException, CardException {
		return readCertificate(FID_AACE);
	}

	public X509Certificate readSignCert() throws EstEIDException, CardException {
		return readCertificate(FID_DDCE);
	}

	// Crypto operations
	public void se_restore(int i) throws EstEIDException, CardException {
		check(transmit(new CommandAPDU(0x00, INS_MANAGE_SECURITY_ENVIRONMENT, 0xF3, i)));
	}

	public void se_keyref(int type, int ref) throws EstEIDException, CardException {
		check(transmit(new CommandAPDU(0x00, INS_MANAGE_SECURITY_ENVIRONMENT, 0x41, type, new byte[] {(byte) 0x83, 0x03, (byte) 0x80, (byte) (ref >> 8), (byte) ref})));
	}

	public byte[] sign(byte[] data, String pin) throws EstEIDException, CardException {
		select(FID_3F00);
		select(FID_EEEE);
		se_restore(1);
		verify(PIN2, pin);
		CommandAPDU cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1P2_PSO_SIGN >> 8, P1P2_PSO_SIGN & 0xFF, data, 256);
		return check(transmit(cmd)).getData();
	}

	public byte[] authenticate(byte[] data, String pin) throws EstEIDException, CardException {
		select(FID_3F00);
		select(FID_EEEE);
		se_restore(1);
		verify(PIN1, pin);
		CommandAPDU cmd = new CommandAPDU(0x00, INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, data, 256);
		return check(transmit(cmd)).getData();
	}

	public byte[] decrypt(byte[] data, String pin)  throws EstEIDException, CardException {
		select(FID_3F00);
		select(FID_EEEE);
		se_restore(6);
		verify(PIN1, pin);
		// Some magic - decryption key reference
		// TODO: discover this from FID 0x0033
		se_keyref(0xB8, 0x1100);
		// prepend 0
		byte[] d = org.bouncycastle.util.Arrays.prepend(data, (byte)0);

		if (d.length > chunksize) {
			// split in two
			byte[] d1 = Arrays.copyOfRange(d, 0, chunksize);
			byte[] d2 = Arrays.copyOfRange(d, chunksize, d.length);
			// send in two parts with chaining
			CommandAPDU cmd = new CommandAPDU(0x10, INS_PERFORM_SECURITY_OPERATION, P1P2_PSO_DECRYPT>>8, P1P2_PSO_DECRYPT & 0xFF, d1, 256);
			check(transmit(cmd));
			cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1P2_PSO_DECRYPT>>8, P1P2_PSO_DECRYPT & 0xFF, d2, 256);
			return check(transmit(cmd)).getData();
		}  else {
			CommandAPDU cmd = new CommandAPDU(0x00, INS_PERFORM_SECURITY_OPERATION, P1P2_PSO_DECRYPT>>8, P1P2_PSO_DECRYPT & 0xFF, d, 256);
			return check(transmit(cmd)).getData();
		}
	}


	private ResponseAPDU transmit(CommandAPDU cmd) throws CardException {
		return card.getBasicChannel().transmit(cmd);
	}

	private static ResponseAPDU check(ResponseAPDU resp) throws EstEIDException {
		if (resp.getSW() != 0x9000)
			throw new EstEIDException(resp.getSW());
		return resp;
	}

	@SuppressWarnings("serial")
	private static class EstEIDException extends RuntimeException {
		private int sw;
		public EstEIDException(int sw) {
			this.sw = sw;
		}

		public String toString() {
			return "Card returned: " + Integer.toHexString(sw).toUpperCase();
		}
		public int getSW() {
			return sw;
		}
	}

	@SuppressWarnings("serial")
	private static class WrongPINException extends RuntimeException {
		private int sw;
		public WrongPINException(int sw) {
			this.sw = sw;
		}

		public String toString() {
			return "PIN: " + sw;
		}
	}

	public void crypto_tests(String pin1, String pin2) throws NoSuchAlgorithmException, NoSuchPaddingException, EstEIDException, CardException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		X509Certificate authcert = readAuthCert();
		System.out.println("Authcert " + authcert.getSubjectX500Principal().getName("RFC1779"));

		// Verify keys vs certificates
		Cipher verify_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		SecureRandom r = SecureRandom.getInstance("SHA1PRNG");
		byte [] rnd = new byte[8];

		r.nextBytes(rnd);
		verify_cipher.init(Cipher.DECRYPT_MODE, authcert.getPublicKey());
		byte[] result = verify_cipher.doFinal(authenticate(rnd, pin1));
		if (!java.util.Arrays.equals(rnd, result)) {
			throw new RuntimeCryptoException("Card and auth key don't match!");
		} else {
			System.out.println("ENCRYPT: OK");
		}

		r.nextBytes(rnd);
		verify_cipher.init(Cipher.ENCRYPT_MODE, authcert.getPublicKey());
		result = verify_cipher.doFinal(rnd);
		if (!java.util.Arrays.equals(rnd, decrypt(result, pin1))) {
			throw new RuntimeCryptoException("Card and auth key don't match on decryption!");
		} else {
			System.out.println("DECRYPT: OK");
		}

		// Signature key
		X509Certificate signcert = readSignCert();
		System.out.println("Signcert " + signcert.getSubjectX500Principal().getName("RFC1779"));

		r.nextBytes(rnd);
		verify_cipher.init(Cipher.DECRYPT_MODE, signcert.getPublicKey());
		result = verify_cipher.doFinal(sign(rnd, pin2));
		if (!java.util.Arrays.equals(rnd, result)) {
			throw new RuntimeCryptoException("Card and sign key don't match!");
		} else {
			System.out.println("ENCRYPT: OK");
		}


	}
}
