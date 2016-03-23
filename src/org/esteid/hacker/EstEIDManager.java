package org.esteid.hacker;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
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

import org.esteid.EstEID;
import org.esteid.EstEID.EstEIDException;
import org.esteid.EstEID.PersonalData;
import org.esteid.hacker.SecureChannel.SecureChannelException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import apdu4j.HexUtils;
import pro.javacard.gp.CapFile;
import pro.javacard.gp.GPData;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPKeySet.GPKey;
import pro.javacard.gp.GPUtils;
import pro.javacard.gp.GlobalPlatform;
import pro.javacard.gp.GlobalPlatform.APDUMode;
import pro.javacard.gp.PlaintextKeys;
import pro.javacard.gp.SessionKeyProvider;

public class EstEIDManager {

	private static Logger logger = LoggerFactory.getLogger(EstEIDManager.class);

	final CardChannel channel;

	public EstEIDManager(CardChannel c) {
		channel = c;
	}


	public static RSAPublicKey generateKey(SecureChannel c, int key) throws CardException, SecureChannelException {
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

	public static void loadCertificate(SecureChannel sc, X509Certificate c, int key) throws CardException, SecureChannelException {
		try {
			// Add 0x80 tailing marker
			byte[] cert = GPUtils.concatenate(c.getEncoded(), new byte[]{(byte) 0x80});
			logger.trace("Storing certificate: {} ", HexUtils.bin2hex(cert) );
			for (int pos = 0, len = 0x6F; pos < cert.length; pos += len) {
				byte [] data = Arrays.copyOfRange(cert, pos, pos + Math.min(len, cert.length - pos));
				byte p1 = (byte) ((key == 0 ? 0x00 : 0x80) + ((pos >> 8) & 0xFF));
				byte p2 = (byte) (pos & 0xFF);
				EstEIDException.check(sc.transmit(new CommandAPDU(0x8C, 0x07, p1, p2, data)));
			}
		} catch (CertificateEncodingException e) {
			throw new RuntimeException("Could not store certificate", e);
		}
	}

	static void write_perso_file(SecureChannel sc, Properties pd) throws CardException, SecureChannelException, UnsupportedEncodingException{
		for(int i = 1; i <= 16; ++i) {
			logger.trace("Writing personal data file record {}", i);
			String record = pd.getProperty("D" + i);
			if (record == null)
				continue;
			byte [] data = record.getBytes("Windows-1252");
			ResponseAPDU r = sc.transmit(new CommandAPDU(0x00, 0x03, i, 0x00, data));
			check(r, "Could not store personal data file record " + i);
		}
	}

	static ResponseAPDU set_personalized(SecureChannel sc) throws CardException, SecureChannelException {
		logger.debug("Setting applet to personalized state");
		return sc.transmit(new CommandAPDU(0x00, 0x04, 0x00, 0x00));
	}

	static ResponseAPDU check(ResponseAPDU r, String... args) throws EstEIDException {
		if (r.getSW() != 0x9000) {
			throw new EstEID.EstEIDException("Kaboom");
		}
		return r;
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

	public static void doit(CardChannel channel, FakeEstEIDCA ca, InputStream props) throws Exception {

		// Load properties
		Properties p = new Properties();
		// Input is UTF-8
		p.load(new InputStreamReader(props, StandardCharsets.UTF_8));


		byte [] gpkey = HexUtils.hex2bin(p.getProperty("GPKEY"));
		byte [] cmk_perso = HexUtils.hex2bin(p.getProperty("CMK_PERSO"));
		byte [] cmk_pin = HexUtils.hex2bin(p.getProperty("CMK_PIN"));
		byte [] cmk_key = HexUtils.hex2bin(p.getProperty("CMK_KEY"));
		byte [] cmk_cert = HexUtils.hex2bin(p.getProperty("CMK_CERT"));

		// Open GlobalPlatform
		GlobalPlatform gp = new GlobalPlatform(channel);
		gp.select();
		SessionKeyProvider kp = PlaintextKeys.fromMasterKey(new GPKey(gpkey, GPKey.Type.DES3));
		gp.openSecureChannel(kp, null, 0, EnumSet.of(APDUMode.ENC));

		// Load the CAP file.
		CapFile cap = new CapFile(new FileInputStream(p.getProperty("APPLET")));
		try {
			gp.deleteAID(cap.getPackageAID(), true);
		} catch (GPException e) {
			System.out.println("Clean card");
		}
		gp.loadCapFile(cap);

		byte[] pin1 = p.getProperty("PIN1").getBytes(StandardCharsets.US_ASCII);
		byte[] pin2 = p.getProperty("PIN2").getBytes(StandardCharsets.US_ASCII);
		byte[] puk = p.getProperty("PUK").getBytes(StandardCharsets.US_ASCII);

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

		byte [] instparams = params.toByteArray();
		instparams = GPUtils.concatenate(new byte[]{(byte)0xC9, (byte) instparams.length}, instparams);

		gp.installAndMakeSelectable(cap.getPackageAID(), cap.getAppletAIDs().get(0), null, (byte) (GPData.cardLockPriv | GPData.defaultSelectedPriv), instparams, null);

		// Select installed applet
		channel.transmit(select_aid_apdu(HexUtils.hex2bin("D23300000045737445494420763335")));

		// Open secure channel and write personal data file.
		SecureChannel sc = SecureChannel.getInstance(channel);
		sc.mutualAuthenticate(cmk_perso, 0);

		write_perso_file(sc, p);
		RSAPublicKey k1 = generateKey(sc, 0);
		RSAPublicKey k2 = generateKey(sc, 1);
		X509Certificate c1 = ca.generateUserCertificate(k1, false, "MARI-LIIS", "MÄNNIK", "47101010033", "mariliis.mannik@eesti.ee");
		X509Certificate c2 = ca.generateUserCertificate(k2, true, "MARI-LIIS", "MÄNNIK", "47101010033", "mariliis.mannik@eesti.ee");
		loadCertificate(sc, c1, 0);
		loadCertificate(sc, c2, 1);
		set_personalized(sc);

		// GET DATA via SC
		//sc.mutualAuthenticate(cmk_pin, 1);
		System.out.println(HexUtils.bin2hex(sc.transmit(new CommandAPDU(0x00, 0xCA, 0x01, 0x00, 0x03)).getBytes()));
	}
}

