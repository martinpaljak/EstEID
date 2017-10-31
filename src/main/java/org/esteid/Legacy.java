package org.esteid;

import apdu4j.HexUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.HashMap;
import java.util.Map;

public final class Legacy {

    static {
        // Add BouncyCastle if not present
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

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
     * @param cmk      CMK master key (16 bytes 2 key 3DES)
     * @param envelope number
     * @return Map of calculated PIN codes
     */
    public static Map<String, String> pins_from_cmk_and_envelope(byte[] cmk, String envelope) {
        byte[] data = envelope.getBytes(StandardCharsets.US_ASCII);
        byte[] key = cgram(cmk, data);
        Map<String, String> pins = string2pins(hex2numbers(HexUtils.bin2hex(cgram(key, data))));
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
     * @param key  2 key 3DES key (16 bytes)
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
}
