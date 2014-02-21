/**
 * Copyright (C) 2014 Martin Paljak
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package esteidhacker;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import openkms.gp.LoggingCardTerminal;
import openkms.gp.TerminalManager;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.Arrays;


public class FakeEstEID {
	// options.
	private static final String OPT_VERSION = "version";
	private static final String OPT_HELP = "help";

	private static final String OPT_GENCA = "genca";
	private static final String OPT_CA = "ca";


	private static final String OPT_GENAUTH = "genauth";
	private static final String OPT_GENSIGN = "gensign";
	private static final String OPT_LOADAUTH = "authcert";
	private static final String OPT_LOADSIGN = "signcert";

	private static final String OPT_NEW = "new";
	private static final String OPT_DATA = "data";

	public static void main(String argv[]) throws Exception {
		OptionSet args = null;
		OptionParser parser = new OptionParser();

		// Generic options
		parser.accepts(OPT_VERSION, "Show information about the program");
		parser.accepts(OPT_HELP, "Show this help");
		parser.accepts(OPT_CA, "Use CA").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_GENCA, "Generate CA").withRequiredArg().ofType(File.class);

		// Generate keys and stuff.
		parser.accepts(OPT_GENAUTH, "Generate auth key + cert");
		parser.accepts(OPT_GENSIGN, "Generate sign key + cert");
		parser.accepts(OPT_LOADAUTH, "Load auth cert").withRequiredArg().ofType(File.class);
		parser.accepts(OPT_LOADSIGN, "Load sign cert").withRequiredArg().ofType(File.class);


		parser.accepts(OPT_NEW, "Generate a new Mariliis Männik");
		parser.accepts(OPT_DATA, "Edit the personal data file");


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
		if (args.has(OPT_HELP)) {
			parser.printHelpOn(System.out);
			System.exit(0);
		}

		FakeEstEIDCA ca = new FakeEstEIDCA();
		if (args.has(OPT_GENCA)) {
			ca.generate();
			ca.storeToFile((File)args.valueOf(OPT_GENCA));
		} else if (args.has(OPT_CA)) {
			ca.loadFromFile((File)args.valueOf(OPT_CA));
		} else throw new IllegalArgumentException("Need some CA!");

		Card card = null;
		try {
			// Connect to card
			CardTerminal term = LoggingCardTerminal.getInstance(TerminalManager.getTheReader());
			card = term.connect("*");
			card.beginExclusive();
			CardChannel channel = card.getBasicChannel();

			if (args.has(OPT_LOADAUTH)) {
				File f = (File) args.valueOf(OPT_LOADAUTH);
				send_cert(channel, f, 1);
			}

			if (args.has(OPT_LOADSIGN)) {
				File f = (File) args.valueOf(OPT_LOADSIGN);
				send_cert(channel, f, 2);
			}

			if (args.has(OPT_GENAUTH)) {
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
				keyGen.initialize(2048);
				KeyPair key = keyGen.generateKeyPair();
				send_key(channel, (RSAPrivateCrtKey) key.getPrivate(), 1);
			}

			if (args.has(OPT_GENSIGN)) {
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
				keyGen.initialize(2048);
				KeyPair key = keyGen.generateKeyPair();
				send_key(channel, (RSAPrivateCrtKey) key.getPrivate(), 2);
			}

			if (args.has(OPT_NEW)) {
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
				keyGen.initialize(2048);
				// Generate keys
				KeyPair auth = keyGen.generateKeyPair();
				KeyPair sign = keyGen.generateKeyPair();
				X509Certificate authcert = ca.generateUserCertificate((RSAPublicKey) auth.getPublic(), false, "JOHN", "CONNOR", "12322323423", "john@skynet.com");
				X509Certificate signcert = ca.generateUserCertificate((RSAPublicKey) auth.getPublic(), true, "JOHN", "CONNOR", "12322323423", "john@skynet.com");

				send_key(channel, (RSAPrivateCrtKey) auth.getPrivate(), 1);
				send_key(channel, (RSAPrivateCrtKey) sign.getPrivate(), 2);
				send_cert(channel, authcert.getEncoded(), 1);
				send_cert(channel, signcert.getEncoded(), 2);
			}

			// make this automagic somehow.
			if (args.has(OPT_DATA)) {
				for (int i = 1; i<= 16; i++) {
					CommandAPDU cmd = new CommandAPDU(0x80, 0x04, i, 0x00, 256);
					ResponseAPDU resp = channel.transmit(cmd);
					check(resp);
					String value = new String(resp.getData(), Charset.forName("UTF-8"));
					System.out.println("Enter new value for: \n" + value);
					String input = System.console().readLine();
					cmd = new CommandAPDU(0x80, 0x04, i, 0x00, input.getBytes("UTF-8"));
					check(channel.transmit(cmd));
				}
			}
		} catch (CardException e) {
			e.printStackTrace();
		} finally {
			if (card != null) {
				card.endExclusive();
				TerminalManager.disconnect(card, true);
			}
		}
	}
	private static void send_cert(CardChannel channel, byte[] cert, int num) throws Exception {
		int chunksize = 253;

		byte [] c = Arrays.append(cert, (byte)0x80);
		for (int i = 0; i<= (c.length / 253); i++) {
			byte []d = new byte[255];
			int off = i*chunksize;

			d[0] = (byte) ((off & 0xFF00) >>> 8);
			d[1] = (byte) (off & 0xFF);
			byte[] chunk = Arrays.copyOfRange(c, i*chunksize, i*chunksize+chunksize);
			System.arraycopy(chunk, 0, d, 2, chunk.length);
			CommandAPDU cmd = new CommandAPDU(0x80, 0x02, num, 0x00, d);
			check(channel.transmit(cmd));
		}
	}
	private static void send_cert(CardChannel channel, File f, int num) throws Exception {
		PEMParser pem = new PEMParser(new InputStreamReader(new FileInputStream(f)));
		X509CertificateHolder auth = (X509CertificateHolder) pem.readObject();
		pem.close();
		send_cert(channel, auth.getEncoded(), num);
	}

	private static void send_key(CardChannel channel, RSAPrivateCrtKey key, int num) throws CardException {
		CommandAPDU cmd = null;
		cmd = new CommandAPDU(0x80, 0x03, num, 0x01, unsigned(key.getPrimeP().toByteArray()));
		check(channel.transmit(cmd));
		cmd = new CommandAPDU(0x80, 0x03, num, 0x02, unsigned(key.getPrimeQ().toByteArray()));
		check(channel.transmit(cmd));
		cmd = new CommandAPDU(0x80, 0x03, num, 0x03, unsigned(key.getPrimeExponentP().toByteArray()));
		check(channel.transmit(cmd));
		cmd = new CommandAPDU(0x80, 0x03, num, 0x04, unsigned(key.getPrimeExponentQ().toByteArray()));
		check(channel.transmit(cmd));
		cmd = new CommandAPDU(0x80, 0x03, num, 0x05, unsigned(key.getCrtCoefficient().toByteArray()));
		check(channel.transmit(cmd));
	}

	private static byte[] unsigned(byte[] value) {
		if (value[0] == 0x00)
			return Arrays.copyOfRange(value, 1, value.length);
		return value;
	}
	private static void check(ResponseAPDU resp) {
		if (resp.getSW() != 0x9000)
			throw new RuntimeException("PROBLEMO AMIGO!");
	}
}



