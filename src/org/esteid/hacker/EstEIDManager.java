package org.esteid.hacker;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Properties;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.esteid.EstEID.EstEIDException;
import org.esteid.hacker.SecureChannel.SecureChannelException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import apdu4j.HexUtils;
import pro.javacard.gp.CapFile;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPKeySet.GPKey;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPRegistryEntry.Privileges;
import pro.javacard.gp.GPUtils;
import pro.javacard.gp.GlobalPlatform;
import pro.javacard.gp.GlobalPlatform.APDUMode;
import pro.javacard.gp.PlaintextKeys;
import pro.javacard.gp.SessionKeyProvider;

public class EstEIDManager {

	private static Logger logger = LoggerFactory.getLogger(EstEIDManager.class);

	final CardChannel channel;
	private Properties properties;

	public EstEIDManager(CardChannel c) {
		channel = c;
	}

	public static EstEIDManager getPersoManager(InputStream props, CardChannel c) throws IOException {
		// Load different options from the
		Properties p = new Properties();
		// Input is UTF-8
		p.load(new InputStreamReader(props, StandardCharsets.UTF_8));
		EstEIDManager mgr = new EstEIDManager(c);
		mgr.properties = p;
		return mgr;
	}

	public static RSAPublicKey generateKey(SecureChannel c, int key) throws CardException, SecureChannelException, EstEIDException {
		CommandAPDU cmd = new CommandAPDU(0x8C, 0x06, 0x01, key);
		ResponseAPDU r = c.transmit(cmd);
		EstEIDException.check(r);
		RSAPublicKeySpec pubspec = buf2pub(r.getData());
		try {
			return (RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(pubspec);
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("Could not create public key", e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Bad environment", e);
		}
	}

	public static void loadCertificate(SecureChannel sc, X509Certificate c, int key) throws CardException, SecureChannelException, EstEIDException {
		try {
			loadCertificate(sc, c.getEncoded(), key);
		} catch (CertificateEncodingException e) {
			throw new RuntimeException("Could not store certificate", e);
		}
	}

	public static void loadCertificate(SecureChannel sc, byte[] c, int key) throws CardException, SecureChannelException, EstEIDException {
		// Add 0x80 tailing marker
		byte[] cert = GPUtils.concatenate(c, new byte[]{(byte) 0x80});
		logger.trace("Storing certificate: {} ", HexUtils.bin2hex(cert) );
		for (int pos = 0, len = 0x6F; pos < cert.length; pos += len) {
			byte [] data = Arrays.copyOfRange(cert, pos, pos + Math.min(len, cert.length - pos));
			byte p1 = (byte) ((key == 0 ? 0x00 : 0x80) + ((pos >> 8) & 0xFF));
			byte p2 = (byte) (pos & 0xFF);
			EstEIDException.check(sc.transmit(new CommandAPDU(0x8C, 0x07, p1, p2, data)));
		}
	}



	static void write_perso_file(SecureChannel sc, Properties p) throws CardException, SecureChannelException, UnsupportedEncodingException, EstEIDException{
		for(int i = 1; i <= 16; ++i) {
			logger.trace("Writing personal data file record {}", i);
			String record = p.getProperty("D" + i);
			if (record == null)
				continue;
			byte [] data = record.getBytes("Windows-1252");
			ResponseAPDU r = sc.transmit(new CommandAPDU(0x00, 0x03, i, 0x00, data));
			EstEIDException.check(r, "Could not store personal data file record " + i);
		}
	}

	void writePersoFile(SecureChannel sc) throws UnsupportedEncodingException, CardException, SecureChannelException, EstEIDException {
		write_perso_file(sc, properties);
	}
	static ResponseAPDU set_personalized(SecureChannel sc) throws CardException, SecureChannelException {
		logger.debug("Setting applet to personalized state");
		return sc.transmit(new CommandAPDU(0x00, 0x04, 0x00, 0x00));
	}

	public static RSAPublicKeySpec buf2pub(byte[]buf)  {
		int offset = 0;
		// Verify tag
		if (buf[offset] != 0x7F)
			throw new RuntimeException("Expected 0x7F at " + offset);
		offset ++;
		if (buf[offset] != 0x49)
			throw new RuntimeException("Expected 0x49 at " + offset);
		offset ++;

		// Now length of sequence
		offset = skipL(buf, offset);

		// tag 81, modulus
		if ((buf[offset] &0xFF)!= 0x81)
			throw new RuntimeException("Expected 0x81 at " + offset);
		offset ++;
		int modlen = getLength(buf, offset);
		offset = skipL(buf, offset);
		byte[] modulus = Arrays.copyOfRange(buf, offset, offset + modlen);
		logger.debug("Modulus: " + HexUtils.bin2hex(modulus));

		// jump to exponent
		offset = offset + modlen;

		// tag 82, exponent
		if ((buf[offset] &0xFF)!= 0x82)
			throw new RuntimeException("Expected 0x82 at " + offset);
		offset ++;
		int explen = getLength(buf, offset);
		offset = skipL(buf, offset);
		byte[] exponent = Arrays.copyOfRange(buf, offset, offset + explen);
		logger.debug("Exponent: " + HexUtils.bin2hex(exponent));

		return new RSAPublicKeySpec(new BigInteger(1, modulus), new BigInteger(1, exponent));
	}

	public static int skipL(byte[] buf, int offset) {
		if ((buf[offset]&0xFF) == 0x82) {
			return offset + 3;
		} else if ((buf[offset]&0xFF) == 0x81) {
			return offset + 2;
		} else if ((buf[offset]&0xFF) < 0x80) {
			return offset + 1;
		}
		throw new RuntimeException("Bad TLV Length at offset " + offset);
	}

	public static int getLength(byte[] data, int offset) {
		if ((data[offset] & 0xFF) == 0x82) {
			return ((data[offset+1] & 0xFF) << 8) | (data[offset+2] & 0xFF);
		} else if ((data[offset] & 0xFF) == 0x81) {
			return (data[offset+1] & 0xFF);
		} else if ((data[offset] & 0xFF) < 0x80) {
			return (data[offset] & 0xFF);
		}
		throw new RuntimeException("Bad L encoding in TLV at offset " + offset);
	}


	public static CommandAPDU select_aid_apdu(byte [] aid) {
		return new CommandAPDU(0x00, 0xA4, 0x04, 0x0C, aid);
	}


	public String getProperty(String name) {
		return properties.getProperty(name);
	}


	public static GlobalPlatform open_gp(CardChannel c, Properties p) throws CardException, GPException {
		byte [] gpkey = HexUtils.hex2bin(p.getProperty("GPKEY"));
		// Open GlobalPlatform
		GlobalPlatform gp = new GlobalPlatform(c);
		gp.select(null);
		SessionKeyProvider kp = PlaintextKeys.fromMasterKey(new GPKey(gpkey, GPKey.Type.DES3));
		gp.openSecureChannel(kp, null, 0, EnumSet.of(APDUMode.ENC));
		return gp;
	}

	public GlobalPlatform openGlobalPlatform() throws CardException, GPException {
		return open_gp(channel, properties);
	}

	public byte[] getCMK(int num) {
		switch (num) {
		case 0:
			return HexUtils.hex2bin(properties.getProperty("CMK_PERSO"));
		case 1:
			return HexUtils.hex2bin(properties.getProperty("CMK_PIN"));
		case 2:
			return HexUtils.hex2bin(properties.getProperty("CMK_KEY"));
		case 3:
			return HexUtils.hex2bin(properties.getProperty("CMK_CERT"));
		default:
			throw new IllegalArgumentException("No such CMK: " + num);
		}
	}


	public static void install_applet(GlobalPlatform gp, Properties p) throws CardException, GPException, IOException {
		// Load the CAP file.
		CapFile cap = new CapFile(new FileInputStream(p.getProperty("APPLET")));
		try {
			// Delete existing instance if present
			gp.deleteAID(cap.getPackageAID(), true);
		} catch (GPException e) {
			System.out.println("Clean card, installing");
		}
		gp.loadCapFile(cap);

		byte [] cmk_perso = HexUtils.hex2bin(p.getProperty("CMK_PERSO"));
		byte [] cmk_pin = HexUtils.hex2bin(p.getProperty("CMK_PIN"));
		byte [] cmk_key = HexUtils.hex2bin(p.getProperty("CMK_KEY"));
		byte [] cmk_cert = HexUtils.hex2bin(p.getProperty("CMK_CERT"));

		byte[] pin1 = p.getProperty("PIN1").getBytes(StandardCharsets.US_ASCII);
		byte[] pin2 = p.getProperty("PIN2").getBytes(StandardCharsets.US_ASCII);
		byte[] puk = p.getProperty("PUK").getBytes(StandardCharsets.US_ASCII);

		byte [] instparams = installation_parameters(cmk_perso, cmk_pin, cmk_key, cmk_cert, pin1, pin2, puk);

		Privileges privs = new Privileges();
		privs.add(Privilege.CardReset);

		gp.installAndMakeSelectable(cap.getPackageAID(), cap.getAppletAIDs().get(0), null, privs, instparams, null);

		// Select installed applet
		gp.getChannel().transmit(select_aid_apdu(cap.getAppletAIDs().get(0).getBytes()));
	}

	public static byte[] installation_parameters(byte[] cmk_perso, byte[] cmk_pin, byte[] cmk_key, byte[] cmk_cert, byte[] pin1, byte [] pin2, byte [] puk) {
		try {
			// Build installation parameters
			ByteArrayOutputStream params = new ByteArrayOutputStream();
			// CMK-s
			params.write(cmk_perso.length);
			params.write(cmk_perso);
			params.write(cmk_pin.length);
			params.write(cmk_pin);
			params.write(cmk_key.length);
			params.write(cmk_key);
			params.write(cmk_cert.length);
			params.write(cmk_cert);
			// PIN-s
			params.write(pin1.length);
			params.write(pin1);
			params.write(pin2.length);
			params.write(pin2);
			params.write(puk.length);
			params.write(puk);

			// Concatenate with header
			byte [] instparams = params.toByteArray();
			instparams = GPUtils.concatenate(new byte[]{(byte)0xC9, (byte) instparams.length}, instparams);
			return instparams;
		}
		catch (IOException e) {
			throw new RuntimeException("Coult not construct installation parameters", e);
		}
	}

	public static void loadPINCodes(SecureChannel sc, String pin1, String pin2, String puk) throws CardException, SecureChannelException, EstEIDException {
		CommandAPDU replace = new CommandAPDU(0x00, 0x05, 0x00, 0x00, GPUtils.concatenate(pin1.getBytes(), pin2.getBytes(), puk.getBytes()));
		EstEIDException.check(sc.transmit(replace), "Could not replace PIN codes");
	}

	public void installApplet(GlobalPlatform gp) throws CardException, GPException, IOException {
		install_applet(gp, properties);
	}
}

