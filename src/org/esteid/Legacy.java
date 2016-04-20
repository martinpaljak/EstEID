package org.esteid;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import apdu4j.HexUtils;

public final class Legacy {
	/**
	 * Given a HEX string, converts it to pure numbers.
	 *
	 * @param s
	 * @return
	 */
	private static String hex2numbers(String s) {
		return s.toUpperCase().replace('A', '0').replace('B', '1').replace('C', '2').replace('D', '3').replace('E', '4').replace('F', '5');
	}

	/**
	 * Given a CMK key and PIN envelope number, return a Map of PIN codes
	 *
	 * @param cmk CMK master key (16 bytes 2 key 3DES)
	 * @param envelope number
	 * @return Map of calculated PIN codes
	 */
	public static Map<String, String> pins_from_cmk_and_envelope(byte[] cmk, String envelope) {
		byte[] key = cgram(cmk, envelope.getBytes());
		Map<String, String> pins = string2pins(hex2numbers(HexUtils.bin2hex(cgram(key, envelope.getBytes()))));
		return pins;
	}

	private static Map<String, String> string2pins(String s) {
		Map<String, String> pins = new HashMap<>();
		pins.put("PIN1", s.substring(0, 4));
		pins.put("PIN2", s.substring(4, 9));
		pins.put("PUK", s.substring(9, 17));
		return pins;
	}

	/**
	 * EstEID kaardi kasutusjuhend, 17.2. Kaardikohaste võtmete tuletamine
	 *
	 * @param key 2 key 3DES key (16 bytes)
	 * @param data any kind of data
	 * @return derived key as byte array
	 */
	public static byte[] cgram(byte[] key, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(new byte[8]));
			byte[] digest = MessageDigest.getInstance("SHA-1").digest(data);
			return cipher.doFinal(digest, 0, 16);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
			throw new RuntimeException("Invalid runtime environment", e);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			throw new IllegalArgumentException("Failed to calculate cryptogram", e);
		}
	}

	// Test vector
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		// EstEID kaardi kasutusjuhend, 17.1
		byte[] cmk1 = HexUtils.hex2bin("A1A1A1A1A1A1A1A1A2A2A2A2A2A2A2A2");
		// http://www.id.ee/index.php?id=30379
		Map<String, String> pins = pins_from_cmk_and_envelope(cmk1, "00000000001");
		System.out.println(pins);
		if (!pins.get("PIN1").equals("0090") || !pins.get("PIN2").equals("01497") || !pins.get("PUK").equals("17258403")) {
			throw new IllegalStateException("Generated invalid PIN codes: " + pins);
		}
	}
}
