/**
 * Copyright (C) 2014-2015 Martin Paljak
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
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javacard.framework.AID;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import openkms.gp.GlobalPlatform;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import pro.javacard.applets.FakeEstEIDApplet;
import pro.javacard.vre.VJCREProvider;
import pro.javacard.vre.VRE;
import apdu4j.HexUtils;
import apdu4j.LoggingCardTerminal;
import apdu4j.TerminalManager;
import esteidhacker.EstEID.CardType;
import esteidhacker.EstEID.PIN;
import esteidhacker.EstEID.PersonalData;


public class CLI {
	// options.
	private static final String OPT_VERSION = "version";
	private static final String OPT_HELP = "help";
	private static final String OPT_DEBUG = "debug";
	private static final String OPT_VERBOSE = "verbose";
	private static final String OPT_INFO = "info";
	private static final String OPT_RELAX = "relax";

	private static final String OPT_CA = "ca";
	private static final String OPT_RESIGN = "resign";
	private static final String OPT_GENAUTH = "genauth";
	private static final String OPT_GENSIGN = "gensign";

	private static final String OPT_AUTHCERT = "authcert";
	private static final String OPT_SIGNCERT = "signcert";
	private static final String OPT_AUTHKEY = "authkey";
	private static final String OPT_SIGNKEY = "signkey";

	private static final String OPT_LIST = "list";
	private static final String OPT_INSTALL = "install";
	private static final String OPT_NEW = "new";
	private static final String OPT_CHECK = "check";

	private static final String OPT_CLONE = "clone";
	private static final String OPT_DATA = "data";

	private static final String OPT_EMULATE = "emulate";
	private static final String OPT_TEST = "test";
	private static final String OPT_TEST_PINS = "test-pins";
	private static final String OPT_TEST_CRYPTO = "test-crypto";


	private static final String OPT_PIN1 = "pin1";
	private static final String OPT_PIN2 = "pin2";
	private static final String OPT_PUK = "puk";

	private static OptionSet parseArguments(String argv[]) throws IOException {
		OptionSet args = null;
		OptionParser parser = new OptionParser();

		// Generic options
		parser.accepts(OPT_VERSION, "Show information about the program");
		parser.acceptsAll(Arrays.asList("h", OPT_HELP), "Show this help");
		parser.acceptsAll(Arrays.asList("d", OPT_DEBUG), "Debug (show APDU-s)");
		parser.acceptsAll(Arrays.asList("v", OPT_VERBOSE), "Be verbose");
		parser.acceptsAll(Arrays.asList("i", OPT_INFO), "Show information about the EstEID token");
		parser.acceptsAll(Arrays.asList("l", OPT_LIST), "List connected tokens");

		parser.accepts(OPT_RELAX, "Relax some checks");

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
		parser.accepts(OPT_INSTALL, "Install FakeEstEID applet").withOptionalArg();
		parser.accepts(OPT_NEW, "Populate a new \"Mari-Liis Männik\"");
		parser.accepts(OPT_CHECK, "Check generated keys for consistency");

		// Clone a card
		parser.accepts(OPT_CLONE, "Clone the card");
		parser.accepts(OPT_DATA, "Edit the personal data file");

		parser.accepts(OPT_EMULATE, "Use FakeEstEIDApplet intance inside vJCRE");
		parser.accepts(OPT_TEST, "Run EstEID test-suite");
		parser.accepts(OPT_TEST_CRYPTO, "Run only crypto tests");
		parser.accepts(OPT_TEST_PINS, "Run only PIN tests");


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

		if (args.has(OPT_HELP)) {
			parser.printHelpOn(System.out);
			System.exit(0);
		}
		return args;
	}

	public static void main(String argv[]) throws Exception {

		String pin1 = EstEID.PIN1String;
		String pin2 = EstEID.PIN2String;
		String puk = EstEID.PUKString;

		OptionSet args = parseArguments(argv);

		// Do the work, based on arguments
		if (args.has(OPT_VERSION)) {
			System.out.println("EstEID hacker v0.1");
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
		} else if (args.has(OPT_EMULATE)) {
			ca.generate();
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
			JcaPEMWriter wr = new JcaPEMWriter(new OutputStreamWriter(System.out));
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
				if (args.has(OPT_LIST)) {
					TerminalFactory tf = TerminalManager.getTerminalFactory(true);
					CardTerminals terms = tf.terminals();
					for (CardTerminal t: terms.list()) {
						EstEID eid = EstEID.getInstance(t);
						String s = "";
						if (t.isCardPresent()) {
							s = ": not EstEID";
							CardType ct = eid.identify();
							if (ct != null) {
								s = ": " + ct.toString();
							}
						}
						System.out.println((t.isCardPresent() ? "[*] " : "[ ] ") + t.getName() + s);
					}
				} else {
					// Connect to a real card
					term = TerminalManager.getTheReader();
				}
			}

			if (args.has(OPT_DEBUG))
				term = LoggingCardTerminal.getInstance(term);

			if (args.has(OPT_CLONE)) {
				// Connect to card.
				System.out.println("Enter card you want to clone and press enter.");
				System.console().readLine();

				EstEID esteid = EstEID.getInstance(term);
				esteid.identify();
				// Read certificates
				X509Certificate authcert = esteid.readAuthCert();
				X509Certificate signcert = esteid.readSignCert();
				// Read personal data file
				HashMap<PersonalData, String> pdf = new HashMap<PersonalData, String>();
				for (PersonalData pd: PersonalData.values()) {
					pdf.put(pd, esteid.getPersonalData(pd));
				}

				esteid.getCard().disconnect(false);
				System.out.println("Enter card with FakeEstEID and press enter.");
				System.console().readLine();
				// XXX: this identify requirement and accessing fake via esteid is silly
				esteid = EstEID.getInstance(term);
				esteid.identify();
				FakeEstEID fake = FakeEstEID.getInstance(esteid);
				fake.send_cert(authcert.getEncoded(), 1);
				fake.send_cert(signcert.getEncoded(), 2);
				// Generate random keys
				fake.send_new_key(1);
				fake.send_new_key(2);
				// Wipe personal data
				CommandAPDU wipe = new CommandAPDU(0x80, 0x04, 0x00, 0x01);
				esteid.getCard().getBasicChannel().transmit(wipe);

				// Store basic data
				for (PersonalData pd: PersonalData.values()) {
					CommandAPDU cmd = new CommandAPDU(0x80, 0x04, pd.getRec(), 0x00, pdf.get(pd).getBytes("ISO8859-15"));
					esteid.getCard().getBasicChannel().transmit(cmd);
				}
				esteid.getCard().disconnect(true);
			}


			if (args.has(OPT_INSTALL)) {
				// Install the applet
				Card c = term.connect("*");
				GlobalPlatform gp = new GlobalPlatform(c.getBasicChannel());
				gp.imFeelingLucky();
				gp.uninstallDefaultSelected(true);
				System.err.println("Use GP utility directly for loading");
				TerminalManager.disconnect(c, true);
			}

			EstEID esteid = EstEID.getInstance(term);
			esteid.identify();

			if (args.has(OPT_RELAX)) {
				esteid.strict = false;
			}

			if (args.has(OPT_VERBOSE) || args.has(OPT_INFO)) {
				System.out.println("ATR: " + HexUtils.encodeHexString(esteid.getCard().getATR().getBytes()));
				System.out.println("Type: " + esteid.getType());
			}

			FakeEstEID fake = FakeEstEID.getInstance(esteid);

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
				fake.send_new_key(1);
			}

			if (args.has(OPT_GENSIGN)) {
				fake.send_new_key(2);
			}

			if (args.has(OPT_NEW) || args.has(OPT_EMULATE)) {
				fake.make_sample_card(ca, args.has(OPT_CHECK));
			}

			// FIXME: this is ugly and bad code.
			if (args.has(OPT_DATA)) {
				for (PersonalData pd: PersonalData.values()) {
					CommandAPDU cmd = new CommandAPDU(0x80, 0x04, pd.getRec(), 0x00, 256);
					ResponseAPDU resp = esteid.getCard().getBasicChannel().transmit(cmd);
					String value = new String(resp.getData(), Charset.forName("ISO8859-15"));
					System.out.println("Enter new value (for " +  pd.name() + "): " + value);
					String input = System.console().readLine();
					cmd = new CommandAPDU(0x80, 0x04, pd.getRec(), 0x00, input.getBytes("ISO8859-15"));
					esteid.getCard().getBasicChannel().transmit(cmd);
				}
			}

			// Following assumes a "ready" card (-new).
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


			if (args.has(OPT_TEST_PINS) || args.has(OPT_TEST)) {
				if (args.has(OPT_PIN1) ^ args.has(OPT_PIN2) || args.has(OPT_PIN2) ^ args.has(OPT_PUK)) {
					System.out.println("Need any or all of PIN options if testing for PINS");
					System.exit(1);
				}
				esteid.pin_tests(pin1, pin2, puk);
			}

			if (args.has(OPT_TEST_CRYPTO) || args.has(OPT_TEST)) {
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
				TerminalManager.disconnect(card, true);
			}
		}
	}
}
