/**
 * Copyright (C) 2014 Martin Paljak
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package esteidhacker;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Map;

import javacard.framework.AID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import openkms.gp.GPUtils;
import openkms.gp.LoggingCardTerminal;
import openkms.gp.TerminalManager;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;

import pro.javacard.applets.FakeEstEIDApplet;
import pro.javacard.vre.VJCREProvider;
import pro.javacard.vre.VRE;
import esteidhacker.EstEID.CardType;
import esteidhacker.EstEID.PIN;
import esteidhacker.EstEID.PersonalData;

public class FakeEstEID {
	// options.
	private static final String OPT_VERSION = "version";
	private static final String OPT_HELP = "help";
	private static final String OPT_DEBUG = "debug";
	private static final String OPT_VERBOSE = "verbose";
	private static final String OPT_INFO = "info";

	private static final String OPT_CA = "ca";
	private static final String OPT_RESIGN = "resign";
	private static final String OPT_GENAUTH = "genauth";
	private static final String OPT_GENSIGN = "gensign";

	private static final String OPT_AUTHCERT = "authcert";
	private static final String OPT_SIGNCERT = "signcert";
	private static final String OPT_AUTHKEY = "authkey";
	private static final String OPT_SIGNKEY = "signkey";

	private static final String OPT_NEW = "new";
	private static final String OPT_CHECK = "check";

	private static final String OPT_DATA = "data";

	private static final String OPT_EMULATE = "emulate";
	private static final String OPT_TEST = "test";

	private static final String OPT_PIN1 = "pin1";
	private static final String OPT_PIN2 = "pin2";
	private static final String OPT_PUK = "puk";



	// Other fun constants
	private static final String[] defaultDataFile = new String[] {"JÄNES-KARVANE", "SIILIPOISS", "Jesús MARIA", "G", "LOL", "01.01.0001", "10101010005", "A0000001", "31.12.2099", "TIIBET", "01.01.2014", "ALALINE", "SEE POLE PÄRIS KAART", " ", " ", " "};
	public static final byte[] aid = new byte[] {(byte)0xD2, (byte)0x33, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x45, (byte)0x73, (byte)0x74, (byte)0x45, (byte)0x49, (byte)0x44, (byte)0x20, (byte)0x76, (byte)0x33, (byte)0x35};

	private final Card card;
	private final CardChannel channel;

	private FakeEstEID(Card card) {
		this.card = card;
		this.channel = card.getBasicChannel();
	}

	public FakeEstEID getInstance(EstEID esteid) {
		if (esteid.getType() == CardType.AnyJavaCard) {
			FakeEstEID fake = new FakeEstEID(esteid.getCard());
			return fake;
		}
		return null;
	}



	public static void main(String argv[]) throws Exception {
		String pin1 = EstEID.PIN1String;
		String pin2 = EstEID.PIN2String;
		String puk = EstEID.PUKString;

		OptionSet args = null;
		OptionParser parser = new OptionParser();

		// Generic options
		parser.accepts(OPT_VERSION, "Show information about the program");
		parser.acceptsAll(Arrays.asList("h", OPT_HELP), "Show this help");
		parser.acceptsAll(Arrays.asList("d", OPT_DEBUG), "Debug (show APDU-s)");
		parser.acceptsAll(Arrays.asList("v", OPT_VERBOSE), "Be verbose");

		// FakeEstEIDCA interface
		parser.accepts(OPT_CA, "Use or generate a CA").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_RESIGN, "Re-sign cert (PEM) with CA").withRequiredArg().ofType(File.class);

		// Generate and load keys/certificates
		parser.accepts(OPT_GENAUTH, "Generate and load auth key + cert from CA");
		parser.accepts(OPT_GENSIGN, "Generate and load sign key + cert from CA");

		// Load keys and certificates.
		parser.accepts(OPT_AUTHCERT, "Load auth cert (PEM)").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_SIGNCERT, "Load sign cert (PEM)").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_AUTHKEY, "Load auth key (PEM)").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_SIGNKEY, "Load sign key (PEM)").withRequiredArg().ofType(File.class);

		// New card generation
		parser.accepts(OPT_NEW, "Generate a new Mari-Liis Männik (or compatible)");
		parser.accepts(OPT_CHECK, "Check generated keys for consistency");

		parser.accepts(OPT_DATA, "Edit the personal data file");

		parser.accepts(OPT_EMULATE, "Use FakeEstEIDApplet intance inside vJCRE");
		parser.accepts(OPT_TEST, "Run the EstEID test-suite");
		parser.accepts(OPT_INFO, "Show information about the EstEID token");

		parser.accepts(OPT_PIN1, "PIN1 of the tested card").withRequiredArg();
		parser.accepts(OPT_PIN2, "PIN2 of the tested card").withRequiredArg();
		parser.accepts(OPT_PUK, "PUK of the tested card").withRequiredArg();




		// Parse arguments
		try {
			args = parser.parse(argv);
			// Try to fetch all values so that format is checked before usage
			for (String s: parser.recognizedOptions().keySet()) {args.valueOf(s);}
		} catch (OptionException e) {
			if (e.getCause() != null) {
				System.err.println(e.getMessage() + ": " + e.getCause().getMessage());
			} else {
				System.err.println(e.getMessage());
			}
			System.err.println();
			parser.printHelpOn(System.err);
			System.exit(1);
		}

		// Do the work, based on arguments
		if (args.has(OPT_VERSION)) {
			System.out.println("EstEID hacker v0.1");
		}

		// Do the work, based on arguments
		if (args.has(OPT_HELP)) {
			parser.printHelpOn(System.out);
			System.exit(0);
		}

		// Load or generate a CA
		FakeEstEIDCA ca = new FakeEstEIDCA();
		if (args.has(OPT_CA)) {
			File f = (File)args.valueOf(OPT_CA);
			if (!f.exists()) {
				ca.generate();
				ca.storeToFile(f);
			} else {
				ca.loadFromFile(f);
			}
		} else if (args.has(OPT_NEW) || args.has(OPT_GENAUTH) || args.has(OPT_GENSIGN) || args.has(OPT_RESIGN)) {
			throw new IllegalArgumentException("Need a CA!");
		}

		if (args.has(OPT_PIN1)) {
			pin1 = (String) args.valueOf(OPT_PIN1);
		}
		if (args.has(OPT_PIN2)) {
			pin2 = (String) args.valueOf(OPT_PIN2);
		}
		if (args.has(OPT_PUK)) {
			puk = (String) args.valueOf(OPT_PUK);
		}

		if (args.has(OPT_RESIGN)) {
			File f = (File) args.valueOf(OPT_RESIGN);
			PEMParser pem = new PEMParser(new FileReader(f));
			X509Certificate crt = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate((X509CertificateHolder) pem.readObject());
			pem.close();

			X509Certificate newcert = ca.cloneUserCertificate((RSAPublicKey) crt.getPublicKey(), crt);
			PEMWriter wr = new PEMWriter(new OutputStreamWriter(System.out));
			wr.writeObject(newcert);
			wr.close();
		}


		Card card = null;
		CardTerminal term = null;

		try {
			if (args.has(OPT_EMULATE)) {
				// Load FakeEstEIDApplet into vJCRE emulator
				VRE vre = VRE.getInstance();
				VRE.debugMode = false;

				AID aid = AID.fromBytes(FakeEstEIDApplet.aid);
				vre.load(FakeEstEIDApplet.class, aid);
				vre.install(aid, true);
				// Establish connection to the applet
				term = TerminalFactory.getInstance("PC/SC", vre, new VJCREProvider()).terminals().list().get(0);
			} else {
				// Connect to a real card
				term = TerminalManager.getTheReader();
			}

			if (args.has(OPT_DEBUG))
				term = LoggingCardTerminal.getInstance(term);

			EstEID esteid = EstEID.getInstance(term);

			if (args.has(OPT_VERBOSE) || args.has(OPT_INFO)) {
				System.out.println("ATR:  " + GPUtils.byteArrayToString(esteid.getCard().getATR().getBytes()));
				System.out.println("Type: " + esteid.getType());
			}

			if (args.has(OPT_INFO)) {
				Map<PIN, Byte> counts = esteid.getPINCounters();

				System.out.print("PIN tries remaining:");
				for (PIN p: PIN.values()) {
					System.out.print(" " + p.toString() + ": " + counts.get(p) + ";");
				}
				System.out.println();

				String docnr = esteid.getPersonalData(PersonalData.DOCUMENT_NR);
				System.out.println("Doc#: " + docnr);
				if (!docnr.startsWith("N")) {
					System.out.println("Cardholder: " + esteid.getPersonalData(PersonalData.GIVEN_NAMES1) + " " + esteid.getPersonalData(PersonalData.SURNAME));
				}
				X509Certificate authcert = esteid.readAuthCert();
				System.out.println("Certificate subject: " + authcert.getSubjectDN());
			}

			FakeEstEID fake = null;
			if (esteid.getType() == CardType.AnyJavaCard) {
				card = term.connect("*");
				fake = new FakeEstEID(card);
			}

			if (args.has(OPT_AUTHCERT)) {
				File f = (File) args.valueOf(OPT_AUTHCERT);
				fake.send_cert_pem(f, 1);
			}

			if (args.has(OPT_SIGNCERT)) {
				File f = (File) args.valueOf(OPT_SIGNCERT);
				fake.send_cert_pem(f, 2);
			}

			if (args.has(OPT_AUTHKEY)) {
				File f = (File) args.valueOf(OPT_AUTHKEY);
				fake.send_key_pem(f, 1);
			}

			if (args.has(OPT_SIGNKEY)) {
				File f = (File) args.valueOf(OPT_SIGNKEY);
				fake.send_key_pem(f, 2);
			}

			if (args.has(OPT_GENAUTH)) {
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
				keyGen.initialize(2048);
				KeyPair key = keyGen.generateKeyPair();
				fake.send_key((RSAPrivateCrtKey) key.getPrivate(), 1);
			}

			if (args.has(OPT_GENSIGN)) {
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
				keyGen.initialize(2048);
				KeyPair key = keyGen.generateKeyPair();
				fake.send_key((RSAPrivateCrtKey) key.getPrivate(), 2);
			}

			if (args.has(OPT_NEW)) {
				fake.make_sample_card(ca, args.has(OPT_CHECK));
			}

			// make this automagic somehow.
			if (args.has(OPT_DATA)) {
				for (int i = 1; i<= 16; i++) {
					CommandAPDU cmd = new CommandAPDU(0x80, 0x04, i, 0x00, 256);
					ResponseAPDU resp = fake.channel.transmit(cmd);
					check(resp);
					String value = new String(resp.getData(), Charset.forName("ISO8859-15"));
					System.out.println("Enter new value for: \n" + value);
					String input = System.console().readLine();
					cmd = new CommandAPDU(0x80, 0x04, i, 0x00, input.getBytes("ISO8859-15"));
					check(fake.channel.transmit(cmd));
				}
			}

			if (args.has(OPT_TEST)) {
				esteid.crypto_tests(pin1, pin2);
			}
		} catch (Exception e) {
			if (TerminalManager.getExceptionMessage(e) != null) {
				System.out.println("PC/SC Error: " + TerminalManager.getExceptionMessage(e));
			} else {
				throw e;
			}
		} finally {
			if (card != null) {
				card.endExclusive();
				TerminalManager.disconnect(card, true);
			}
		}
	}

	public void send_cert(byte[] cert, int num) throws Exception {
		int chunksize = 240; // was:253
		card.beginExclusive();
		try {
			byte [] c = org.bouncycastle.util.Arrays.append(cert, (byte)0x80);
			for (int i = 0; i<= (c.length / chunksize); i++) {
				byte []d = new byte[2+chunksize];
				int off = i*chunksize;

				d[0] = (byte) ((off & 0xFF00) >>> 8);
				d[1] = (byte) (off & 0xFF);
				byte[] chunk = Arrays.copyOfRange(c, i*chunksize, i*chunksize+chunksize);
				System.arraycopy(chunk, 0, d, 2, chunk.length);
				CommandAPDU cmd = new CommandAPDU(0x80, 0x02, num, 0x00, d);
				check(channel.transmit(cmd));
			}
		} finally {
			card.endExclusive();
		}
	}

	public void send_cert_pem(File f, int num) throws Exception {
		PEMParser pem = new PEMParser(new InputStreamReader(new FileInputStream(f)));
		X509CertificateHolder crt = (X509CertificateHolder) pem.readObject();
		pem.close();
		send_cert(crt.getEncoded(), num);
	}
	public void send_key_pem(File f, int num) throws Exception {
		PEMParser pem = new PEMParser(new InputStreamReader(new FileInputStream(f)));
		RSAPrivateCrtKey key = (RSAPrivateCrtKey) pem.readObject();
		pem.close();
		send_cert(key.getEncoded(), num);
	}

	public void send_key(RSAPrivateCrtKey key, int num) throws CardException {
		card.beginExclusive();
		try {
			CommandAPDU cmd = null;
			cmd = new CommandAPDU(0x80, 0x03, num, 0x01, unsigned(key.getPrimeP()));
			check(channel.transmit(cmd));
			cmd = new CommandAPDU(0x80, 0x03, num, 0x02, unsigned(key.getPrimeQ()));
			check(channel.transmit(cmd));
			cmd = new CommandAPDU(0x80, 0x03, num, 0x03, unsigned(key.getPrimeExponentP()));
			check(channel.transmit(cmd));
			cmd = new CommandAPDU(0x80, 0x03, num, 0x04, unsigned(key.getPrimeExponentQ()));
			check(channel.transmit(cmd));
			cmd = new CommandAPDU(0x80, 0x03, num, 0x05, unsigned(key.getCrtCoefficient()));
			check(channel.transmit(cmd));
		} finally {
			card.endExclusive();
		}
	}

	public void make_sample_card(FakeEstEIDCA ca, boolean check) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
		keyGen.initialize(2048);
		// Generate keys
		KeyPair auth = keyGen.generateKeyPair();
		KeyPair sign = keyGen.generateKeyPair();
		X509Certificate authcert = ca.generateUserCertificate((RSAPublicKey) auth.getPublic(), false, "SIILIPOISS", "UDUS", "10101010005", "kalevipoeg@soome.fi");
		X509Certificate signcert = ca.generateUserCertificate((RSAPublicKey) sign.getPublic(), true, "SIILIPOISS", "UDUS", "10101010005", "kalevipoeg@soome.fi");
		if (check) {
			// Verify softkeys
			if (!verifyKeypairIntegrity((RSAPrivateCrtKey)auth.getPrivate(), (RSAPublicKey)authcert.getPublicKey())) {
				throw new RuntimeCryptoException("Cert and key mismatch");
			}
			if (!verifyKeypairIntegrity((RSAPrivateCrtKey)sign.getPrivate(), (RSAPublicKey)signcert.getPublicKey())) {
				throw new RuntimeCryptoException("Cert and key mismatch");
			}
		}
		send_key((RSAPrivateCrtKey) auth.getPrivate(), 1);
		send_key((RSAPrivateCrtKey) sign.getPrivate(), 2);
		send_cert(authcert.getEncoded(), 1);
		send_cert(signcert.getEncoded(), 2);

		CommandAPDU cmd = null;
		ResponseAPDU resp = null;
		if (check) {
			// Verify on-card keys.
			Cipher verify_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			SecureRandom r = SecureRandom.getInstance("SHA1PRNG");
			byte [] rnd = new byte[8];

			r.nextBytes(rnd);
			cmd = new CommandAPDU(0x00, 0x88, 0x00, 0x00, rnd, 256);
			resp = channel.transmit(cmd);
			check(resp);
			verify_cipher.init(Cipher.DECRYPT_MODE, authcert.getPublicKey());
			byte[] result = verify_cipher.doFinal(resp.getData());
			if (!java.util.Arrays.equals(rnd, result)) {
				throw new RuntimeCryptoException("Card and auth key don't match!");
			}

			r.nextBytes(rnd);
			cmd = new CommandAPDU(0x00, 0x2A, 0x9E, 0x9A, rnd, 256);
			resp = channel.transmit(cmd);
			check(resp);
			verify_cipher.init(Cipher.DECRYPT_MODE, signcert.getPublicKey());
			result = verify_cipher.doFinal(resp.getData());
			if (!java.util.Arrays.equals(rnd, result)) {
				throw new RuntimeCryptoException("Card and sign key don't match!");
			}
		}
		// Dump default data file
		for (int i=0;i<defaultDataFile.length; i++) {
			cmd = new CommandAPDU(0x80, 0x04, i+1, 0x00, defaultDataFile[i].toUpperCase().getBytes("ISO8859-15"));
			resp = channel.transmit(cmd);
			check(resp);
		}
	}

	private static byte[] unsigned(BigInteger num) {
		byte[] bytes = num.toByteArray();
		if (bytes.length % 8 == 0) {
			return bytes;
		} else if (bytes[0] == 0x00)
			return Arrays.copyOfRange(bytes, 1, bytes.length);
		return bytes;
	}

	private static void check(ResponseAPDU resp) {
		if (resp.getSW() != 0x9000)
			throw new RuntimeException("PROBLEMO AMIGO!");
	}

	private static boolean verifyKeypairIntegrity(RSAPrivateCrtKey privkey, RSAPublicKey pubkey) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		byte[] nonce = new byte[16];
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		Cipher verify_cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		sr.nextBytes(nonce);
		verify_cipher.init(Cipher.ENCRYPT_MODE, pubkey);
		byte[] cryptogram = verify_cipher.doFinal(nonce);
		verify_cipher.init(Cipher.DECRYPT_MODE, privkey);
		byte[] result = verify_cipher.doFinal(cryptogram);
		if (!Arrays.equals(nonce, result))
			return false;

		sr.nextBytes(nonce);
		verify_cipher.init(Cipher.ENCRYPT_MODE, privkey);
		cryptogram = verify_cipher.doFinal(nonce);
		verify_cipher.init(Cipher.DECRYPT_MODE, pubkey);
		result = verify_cipher.doFinal(cryptogram);
		if (!Arrays.equals(nonce, result))
			return false;

		return true;
	}
}



