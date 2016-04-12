/**
 * Copyright (C) 2014-2016 Martin Paljak
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
package org.esteid.hacker;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.Charset;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;

import apdu4j.HexUtils;
import apdu4j.LoggingCardTerminal;
import apdu4j.TerminalManager;
import javacard.framework.AID;
import jnasmartcardio.Smartcardio.EstablishContextException;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;

import org.esteid.EstEID;
import org.esteid.EstEID.CardType;
import org.esteid.EstEID.PIN;
import org.esteid.EstEID.PersonalData;

import pro.javacard.gp.GlobalPlatform;
import pro.javacard.vre.VJCREProvider;
import pro.javacard.vre.VRE;


public class CLI {
	// options.
	private static final String OPT_VERSION = "version";
	private static final String OPT_HELP = "help";
	private static final String OPT_DEBUG = "debug";
	private static final String OPT_INFO = "info";

	private static final String OPT_CA = "ca";
	private static final String OPT_DUMP = "dump";

	private static final String OPT_RESIGN = "resign";
	private static final String OPT_GENAUTH = "genauth";
	private static final String OPT_GENSIGN = "gensign";

	private static final String OPT_AUTHCERT = "authcert";
	private static final String OPT_SIGNCERT = "signcert";
	private static final String OPT_AUTHKEY = "authkey";
	private static final String OPT_SIGNKEY = "signkey";

	private static final String OPT_LIST = "list";
	private static final String OPT_PERSO = "perso";
	private static final String OPT_NEW = "new";
	private static final String OPT_CHECK = "check";
	private static final String OPT_INSTALL = "install";
	private static final String OPT_FINALIZE = "finalize";

	private static final String OPT_CLONE = "clone";
	private static final String OPT_DATA = "data";

	private static final String OPT_EMULATE = "emulate";
	private static final String OPT_TEST = "test";
	private static final String OPT_TEST_PINS = "test-pins";
	private static final String OPT_TEST_CRYPTO = "test-crypto";
	private static final String OPT_COUNTERS = "counters";
	private static final String OPT_LOADPINS = "loadpins";


	private static final String OPT_PIN1 = "pin1";
	private static final String OPT_PIN2 = "pin2";
	private static final String OPT_PUK = "puk";
	private static final String OPT_CMK = "cmk";
	private static final String OPT_KEY = "key";


	private static final String OPT_T0 = "t0";
	private static final String OPT_T1 = "t1";
	private static final String OPT_EXCLUSIVE = "exclusive";


	private static OptionSet parseArguments(String argv[]) throws IOException {
		OptionSet args = null;
		OptionParser parser = new OptionParser();

		// Generic options
		parser.accepts(OPT_VERSION, "Show information about the program");
		parser.acceptsAll(Arrays.asList("h", OPT_HELP), "Show this help");
		parser.acceptsAll(Arrays.asList("d", OPT_DEBUG), "Debug (show APDU-s)");
		parser.acceptsAll(Arrays.asList("i", OPT_INFO), "Show information about the EstEID token");
		parser.acceptsAll(Arrays.asList("l", OPT_LIST), "List connected tokens");

		// FakeEstEIDManagerCA interface
		parser.accepts(OPT_CA, "Use or generate a CA").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_DUMP, "Dump CA keys");

		parser.accepts(OPT_RESIGN, "Re-sign cert with CA").withRequiredArg().ofType(File.class);

		// Generate and load keys/certificates
		parser.accepts(OPT_GENAUTH, "Generate auth key (+ cert)");
		parser.accepts(OPT_GENSIGN, "Generate sign key (+ cert)");

		// Load keys and certificates.
		parser.accepts(OPT_AUTHCERT, "Load auth cert (PEM)").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_SIGNCERT, "Load sign cert (PEM)").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_AUTHKEY, "Load auth key (PEM)").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_SIGNKEY, "Load sign key (PEM)").withRequiredArg().ofType(File.class);

		// New card generation
		parser.accepts(OPT_PERSO, "Personalize a card").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_NEW, "Populate a new \"Mari-Liis Männik\"");
		parser.accepts(OPT_CHECK, "Check generated keys for consistency");
		parser.accepts(OPT_INSTALL, "Install applet");
		parser.accepts(OPT_DATA, "Edit or write the personal data file");
		parser.accepts(OPT_FINALIZE, "Finalize personalization");


		// Clone a card
		parser.accepts(OPT_CLONE, "Clone the card");

		parser.accepts(OPT_EMULATE, "Emulate applet from JAR").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_TEST, "Run EstEID test-suite");
		parser.accepts(OPT_TEST_CRYPTO, "Run only crypto tests");
		parser.accepts(OPT_TEST_PINS, "Run only PIN tests");

		parser.accepts(OPT_PIN1, "PIN1 of the tested card").withRequiredArg();
		parser.accepts(OPT_PIN2, "PIN2 of the tested card").withRequiredArg();
		parser.accepts(OPT_PUK, "PUK of the tested card").withRequiredArg();

		// CMK authentication and related tasks
		parser.accepts(OPT_CMK, "Use CMK X").withRequiredArg().ofType(Integer.class);
		parser.accepts(OPT_KEY, "CMK X value").withRequiredArg();
		parser.accepts(OPT_COUNTERS, "Read counters");
		parser.accepts(OPT_LOADPINS, "Load new PIN codes");

		// Technical options
		parser.accepts(OPT_T0, "Use T=0");
		parser.accepts(OPT_T1, "Use T=1");
		parser.accepts(OPT_EXCLUSIVE, "Use exclusive mode");


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

		// Default PIN strings
		String pin1 = EstEID.PIN1String;
		String pin2 = EstEID.PIN2String;
		String puk = EstEID.PUKString;

		OptionSet args = parseArguments(argv);

		// Do the work, based on arguments
		if (args.has(OPT_VERSION)) {
			System.out.println("EstEID hacker " + EstEID.getVersion());
		}

		if (args.has(OPT_DEBUG)) {
			// Set up slf4j simple in a way that pleases us
			System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
			System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
			System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");
			System.setProperty("org.slf4j.simpleLogger.levelInBrackets", "true");
		} else {
			System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "warn");
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
			if (args.has(OPT_DUMP)) {
				System.out.println(crt2pem(ca.getRootCert()));
				System.out.println(crt2pem(ca.getIntermediateCert()));
			}
		} else if (args.has(OPT_EMULATE)) {
			ca.generate();
		} else if (args.has(OPT_NEW) || args.has(OPT_RESIGN)) {
			System.err.println("Need a CA!");
			System.exit(1);
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

		// Resign a certificate with the fake CA.
		if (args.has(OPT_RESIGN)) {
			File f = (File) args.valueOf(OPT_RESIGN);
			PEMParser pem = new PEMParser(new FileReader(f));
			X509Certificate crt = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate((X509CertificateHolder) pem.readObject());
			pem.close();

			X509Certificate newcert = ca.cloneUserCertificate((RSAPublicKey) crt.getPublicKey(), crt);
			System.out.println(crt2pem(newcert));
		}

		Card card = null;
		CardTerminal term;

		try {
			if (args.has(OPT_EMULATE)) {
				// Load FakeEstEIDManagerApplet into vJCRE emulator
				VRE vre = VRE.getInstance();
				AID aid = AID.fromBytes(FakeEstEIDManager.aid);
				// Load the class from specified JAR.
				final Class<?> cls;
				try (URLClassLoader loader = new URLClassLoader(new URL[] { ((File)args.valueOf(OPT_EMULATE)).toURI().toURL()}, CLI.class.getClassLoader())) {
					cls = loader.loadClass("org.esteid.applet.FakeEstEID");
				}
				vre.load(cls, aid);
				vre.install(aid, true);
				// Establish connection to the applet
				term = TerminalFactory.getInstance("PC/SC", vre, new VJCREProvider()).terminals().list().get(0);
			} else {
				if (args.has(OPT_LIST)) {
					// Use the default
					TerminalFactory tf = TerminalManager.getTerminalFactory(null);
					CardTerminals terms = tf.terminals();
					System.out.println("Found terminals: " + terms.list().size());
					for (CardTerminal t: terms.list()) {
						String s = "";
						if (t.isCardPresent()) {
							s = ": not EstEID";
							CardType ct = EstEID.identify(t);
							if (ct != null) {
								s = ": " + ct.toString();
							}
						}
						System.out.println((t.isCardPresent() ? "[*] " : "[ ] ") + t.getName() + s);
					}
				}
				// Connect to the found reader.
				term = TerminalManager.getTheReader(null);
			}

			if (args.has(OPT_DEBUG)) {
				term = LoggingCardTerminal.getInstance(term);
			}

			if (args.has(OPT_CLONE)) {
				// Connect to card.
				System.out.println("Enter card you want to clone and press enter.");
				System.console().readLine();

				card = term.connect("*");

				EstEID esteid = EstEID.getInstance(card.getBasicChannel());
				// Read certificates
				X509Certificate authcert = esteid.readAuthCert();
				X509Certificate signcert = esteid.readSignCert();
				// Read personal data file
				HashMap<PersonalData, String> pdf = new HashMap<PersonalData, String>();
				for (PersonalData pd: PersonalData.values()) {
					pdf.put(pd, esteid.getPersonalData(pd));
				}

				// Disconnect
				card.disconnect(true);
				System.out.println("Enter card with FakeEstEIDManager and press enter.");
				System.console().readLine();

				card = term.connect("*");
				esteid = EstEID.getInstance(card.getBasicChannel());
				FakeEstEIDManager fake = FakeEstEIDManager.getInstance(esteid);
				fake.send_cert(authcert.getEncoded(), 1);
				fake.send_cert(signcert.getEncoded(), 2);
				// Generate random keys
				fake.send_new_key(1);
				fake.send_new_key(2);
				// Wipe personal data
				CommandAPDU wipe = new CommandAPDU(0x80, 0x04, 0x00, 0x01);
				esteid.transmit(wipe);

				// Store basic data
				for (PersonalData pd: PersonalData.values()) {
					CommandAPDU cmd = new CommandAPDU(0x80, 0x04, pd.getRec(), 0x00, pdf.get(pd).getBytes("ISO8859-15"));
					esteid.transmit(cmd);
				}
				card.disconnect(true);
			}

			String protocol = "*";
			if (args.has(OPT_T0))
				protocol = "T=0";
			else if (args.has(OPT_T1))
				protocol = "T=1";

			if (args.has(OPT_EXCLUSIVE)) {
				protocol = "EXCLUSIVE;" + protocol;
			}

			card = term.connect(protocol);

			// We use JNA, thus the exclusive access results in SCardBeginTransaction()
			card.beginExclusive();

			EstEID esteid = EstEID.getInstance(card.getBasicChannel());

			if (args.has(OPT_PERSO)) {
				// Personalization
				EstEIDManager mgr = EstEIDManager.getPersoManager(new FileInputStream((File)args.valueOf(OPT_PERSO)), card.getBasicChannel());
				if (args.has(OPT_NEW)) {
					// install applet
					GlobalPlatform gp = mgr.openGlobalPlatform();
					mgr.installApplet(gp);
					// Generate keys.
					SecureChannel sc = SecureChannel.getInstance(gp.getChannel());
					sc.mutualAuthenticate(mgr.getCMK(0), 0);

					mgr.writePersoFile(sc);
					RSAPublicKey k1 = EstEIDManager.generateKey(sc, 0);
					RSAPublicKey k2 = EstEIDManager.generateKey(sc, 1);

					// Generate fake certificates
					X509Certificate c1 = ca.generateUserCertificate(k1, false, mgr.getProperty("D2"), mgr.getProperty("D1"), mgr.getProperty("D7"), mgr.getProperty("EMAIL"));
					X509Certificate c2 = ca.generateUserCertificate(k2, true, mgr.getProperty("D2"), mgr.getProperty("D1"), mgr.getProperty("D7"), mgr.getProperty("EMAIL"));

					// Load certificates
					EstEIDManager.loadCertificate(sc, c1, 0);
					EstEIDManager.loadCertificate(sc, c2, 1);

					// Set to personalized
					EstEIDManager.set_personalized(sc);
				} else if (args.has(OPT_INSTALL)) {
					// Only intall the application
					GlobalPlatform gp = mgr.openGlobalPlatform();
					mgr.installApplet(gp);// install applet
				} else {
					// Everything else assumes installed application with CMK 0
					SecureChannel sc = SecureChannel.getInstance(card.getBasicChannel());
					sc.mutualAuthenticate(mgr.getCMK(0), 0);

					if (args.has(OPT_DATA)) {
						// Write personal data file
						mgr.writePersoFile(sc);
					}
					if (args.has(OPT_GENAUTH)) {
						RSAPublicKey pubkey = EstEIDManager.generateKey(sc, 0);
						if (args.has(OPT_CA)) {
							X509Certificate crt = ca.generateUserCertificate(pubkey, false,  mgr.getProperty("D2"), mgr.getProperty("D1"), mgr.getProperty("D7"), mgr.getProperty("EMAIL"));
							EstEIDManager.loadCertificate(sc, crt.getEncoded(), 0);
							System.out.println("Loaded and generated: " + crt.getSubjectDN());
						} else {
							System.out.println(pub2pem(pubkey));
						}
					}

					if (args.has(OPT_GENSIGN)) {
						RSAPublicKey pubkey = EstEIDManager.generateKey(sc, 1);
						if (args.has(OPT_CA)) {
							X509Certificate crt = ca.generateUserCertificate(pubkey, true,  mgr.getProperty("D2"), mgr.getProperty("D1"), mgr.getProperty("D7"), mgr.getProperty("EMAIL"));
							EstEIDManager.loadCertificate(sc, crt.getEncoded(), 1);
							System.out.println("Loaded and generated: " + crt.getSubjectDN());
						} else {
							System.out.println(pub2pem(pubkey));
						}
					}
					if (args.has(OPT_AUTHCERT)) {
						PEMParser pem = new PEMParser(new InputStreamReader(new FileInputStream((File)args.valueOf(OPT_AUTHCERT))));
						X509CertificateHolder crt = (X509CertificateHolder) pem.readObject();
						pem.close();
						EstEIDManager.loadCertificate(sc, crt.getEncoded(), 0);
					}
					if (args.has(OPT_SIGNCERT)) {
						PEMParser pem = new PEMParser(new InputStreamReader(new FileInputStream((File)args.valueOf(OPT_SIGNCERT))));
						X509CertificateHolder crt = (X509CertificateHolder) pem.readObject();
						pem.close();
						EstEIDManager.loadCertificate(sc, crt.getEncoded(), 1);
					}
					if (args.has(OPT_FINALIZE)) {
						EstEIDManager.set_personalized(sc);
					}
				}
			} else if (args.has(OPT_CMK) && args.has(OPT_KEY)) {
				// Post-perso. Requires PIN, so use it if presented.
				if (args.has(OPT_PIN1) && !args.has(OPT_LOADPINS)) {
					card.getBasicChannel().transmit(EstEID.verify_apdu(EstEID.PIN1, (String)args.valueOf(OPT_PIN1)));
				}
				SecureChannel sc = SecureChannel.getInstance(card.getBasicChannel());
				sc.mutualAuthenticate(HexUtils.hex2bin((String)args.valueOf(OPT_KEY)), (Integer)args.valueOf(OPT_CMK));
				if (args.has(OPT_LOADPINS)) {
					EstEIDManager.loadPINCodes(sc, pin1, pin2, puk);
					System.out.println("PIN codes set: PIN1:" + pin1 + " PIN2:" + pin2 + " PUK:" + puk);
				} else if (args.has(OPT_COUNTERS)) {
					System.out.println(HexUtils.bin2hex(sc.transmit(new CommandAPDU(HexUtils.hex2bin("00CA040000"))).getBytes()));
				} else if (args.has(OPT_GENAUTH)) {
					RSAPublicKey pubkey = EstEIDManager.generateKey(sc, 0);
					System.out.println(pub2pem(pubkey));
				} else 	if (args.has(OPT_GENSIGN)) {
					RSAPublicKey pubkey = EstEIDManager.generateKey(sc, 1);
					System.out.println(pub2pem(pubkey));
				} else if (args.has(OPT_AUTHCERT)) {
					PEMParser pem = new PEMParser(new InputStreamReader(new FileInputStream((File)args.valueOf(OPT_AUTHCERT))));
					X509CertificateHolder crt = (X509CertificateHolder) pem.readObject();
					pem.close();
					EstEIDManager.loadCertificate(sc, crt.getEncoded(), 0);
				} else if (args.has(OPT_SIGNCERT)) {
					PEMParser pem = new PEMParser(new InputStreamReader(new FileInputStream((File)args.valueOf(OPT_SIGNCERT))));
					X509CertificateHolder crt = (X509CertificateHolder) pem.readObject();
					pem.close();
					EstEIDManager.loadCertificate(sc, crt.getEncoded(), 1);
				}
			} else {
				// Fake
				FakeEstEIDManager fake = FakeEstEIDManager.getInstance(esteid);

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
						ResponseAPDU resp = esteid.transmit(cmd);
						String value = new String(resp.getData(), Charset.forName("ISO8859-15"));
						System.out.println("Enter new value (for " +  pd.name() + "): " + value);
						String input = System.console().readLine();
						cmd = new CommandAPDU(0x80, 0x04, pd.getRec(), 0x00, input.getBytes("ISO8859-15"));
						esteid.transmit(cmd);
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
		} catch (CardException | EstablishContextException e) {
			if (TerminalManager.getExceptionMessage(e) != null) {
				System.out.println("PC/SC Error: " + TerminalManager.getExceptionMessage(e));
			} else {
				System.out.println("Error: " + e.getMessage());
			}
		} finally {
			if (card != null) {
				card.endExclusive();
				card.disconnect(true);
			}
		}
	}
	static String pub2pem(RSAPublicKey p) {
		return "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString(p.getEncoded()) + "\n-----END PUBLIC KEY-----";
	}
	static String crt2pem(X509Certificate c) throws CertificateEncodingException {
		return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(c.getEncoded()) + "\n-----END CERTIFICATE-----";
	}

}
