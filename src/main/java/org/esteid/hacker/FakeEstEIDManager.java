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
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.RuntimeCryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.esteid.EstEID;
import org.esteid.EstEID.EstEIDException;

// Given a connection to a FakeEstEID applet, provides a higher level interface for the possibilities.
public class FakeEstEIDManager {

	// Other fun constants
	private static final String[] defaultDataFile = new String[] {"JÄNES-KARVANE", "SIILIPOISS", "Jesús MARIA", "G", "LOL", "01.01.0001", "10101010005", "A0000001", "31.12.2099", "TIIBET", "01.01.2014", "ALALINE", "SEE POLE PÄRIS KAART", " ", " ", " "};

	private final CardChannel channel;

	FakeEstEIDManager(CardChannel c) {
		channel = c;
	}

	public static FakeEstEIDManager getInstance(EstEID esteid) {
		FakeEstEIDManager fake = new FakeEstEIDManager(esteid.getChannel());
		return fake;
	}

	public void send_cert(byte[] cert, int num) throws Exception {
		int chunksize = 240; // was:253

		byte [] c = org.bouncycastle.util.Arrays.append(cert, (byte)0x80);
		for (int i = 0; i<= (c.length / chunksize); i++) {
			byte []d = new byte[2+chunksize];
			int off = i*chunksize;

			d[0] = (byte) ((off & 0xFF00) >>> 8);
			d[1] = (byte) (off & 0xFF);
			byte[] chunk = Arrays.copyOfRange(c, i*chunksize, i*chunksize+chunksize);
			System.arraycopy(chunk, 0, d, 2, chunk.length);
			CommandAPDU cmd = new CommandAPDU(0x80, 0x02, num, 0x00, d);
			EstEIDException.check(channel.transmit(cmd));
		}

	}

	public void send_cert_pem(File f, int num) throws Exception {
		try (PEMParser pem = new PEMParser(new InputStreamReader(new FileInputStream(f), "UTF-8"))) {
			X509CertificateHolder crt = (X509CertificateHolder) pem.readObject();
			send_cert(crt.getEncoded(), num);
		}
	}

	public void send_new_key(int num) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		//keyGen.initialize(new RSAKeyGenParameterSpec(2048, BigInteger.ONE));
		KeyPair key = keyGen.generateKeyPair();
		send_key((RSAPrivateCrtKey) key.getPrivate(), num);
	}

	public void send_key_pem(File f, int num) throws Exception {
		try (PEMParser pem = new PEMParser(new InputStreamReader(new FileInputStream(f), "UTF-8"))) {
			// OpenSSL genrsa makes a key pair.
			Object o = pem.readObject();
			RSAPrivateCrtKey key;
			if (o instanceof org.bouncycastle.openssl.PEMKeyPair) {
				PEMKeyPair pair = (PEMKeyPair) o;
				JcaPEMKeyConverter convert = new JcaPEMKeyConverter();
				key = (RSAPrivateCrtKey) convert.getPrivateKey(pair.getPrivateKeyInfo());
			} else {
				key = (RSAPrivateCrtKey) pem.readObject();
			}
			send_key(key, num);
		}
	}

	public void send_key(RSAPrivateCrtKey key, int num) throws CardException, EstEIDException {
		//card.beginExclusive();
		try {
			CommandAPDU cmd = null;
			cmd = new CommandAPDU(0x80, 0x03, num, 0x01, unsigned(key.getPrimeP()));
			EstEIDException.check(channel.transmit(cmd));
			cmd = new CommandAPDU(0x80, 0x03, num, 0x02, unsigned(key.getPrimeQ()));
			EstEIDException.check(channel.transmit(cmd));
			cmd = new CommandAPDU(0x80, 0x03, num, 0x03, unsigned(key.getPrimeExponentP()));
			EstEIDException.check(channel.transmit(cmd));
			cmd = new CommandAPDU(0x80, 0x03, num, 0x04, unsigned(key.getPrimeExponentQ()));
			EstEIDException.check(channel.transmit(cmd));
			cmd = new CommandAPDU(0x80, 0x03, num, 0x05, unsigned(key.getCrtCoefficient()));
			EstEIDException.check(channel.transmit(cmd));
		} finally {
			//card.endExclusive();
		}
	}

	public void make_sample_card(FakeEstEIDCA ca, boolean check) throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
		keyGen.initialize(2048);
		// Generate keys
		KeyPair auth = keyGen.generateKeyPair();
		KeyPair sign = keyGen.generateKeyPair();
		X509Certificate authcert = ca.generateUserCertificate((RSAPublicKey) auth.getPublic(), false, "SIILIPOISS", "UDUS", "10101010005", "kalevipoeg@soome.fi", null, null);
		X509Certificate signcert = ca.generateUserCertificate((RSAPublicKey) sign.getPublic(), true, "SIILIPOISS", "UDUS", "10101010005", "kalevipoeg@soome.fi", null, null);
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
			EstEIDException.check(resp);
			verify_cipher.init(Cipher.DECRYPT_MODE, authcert.getPublicKey());
			byte[] result = verify_cipher.doFinal(resp.getData());
			if (!java.util.Arrays.equals(rnd, result)) {
				throw new RuntimeCryptoException("Card and auth key don't match!");
			}

			r.nextBytes(rnd);
			cmd = new CommandAPDU(0x00, 0x2A, 0x9E, 0x9A, rnd, 256);
			resp = channel.transmit(cmd);
			EstEIDException.check(resp);
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
			EstEIDException.check(resp);
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



