/**
 * Copyright (c) 2014-2017 Martin Paljak
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
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
        // Add BouncyCastle if not present, used for DESede/CBC/NoPadding
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Given a HEX string, converts it to pure numbers.
     * <p>
     * FIXME: specification source
     *
     * @param s hex string
     * @return a string containing only numbers
     */
    public static String hex2numbers(String s) {
        return s.toUpperCase().replace('A', '0').replace('B', '1').replace('C', '2').replace('D', '3').replace('E', '4').replace('F', '5');
    }

    /**
     * Given a CMK key and PIN envelope number, return a Map of PIN codes
     * <p>
     * FIXME: specification source
     *
     * @param cmk      CMK master key (16 bytes 2 key 3DES)
     * @param envelope number
     * @return Map of calculated PIN codes
     */
    public static Map<String, String> pins_from_cmk_and_envelope(byte[] cmk, String envelope) {
        byte[] data = envelope.getBytes(StandardCharsets.US_ASCII);
        // Derive per-envelope key
        byte[] key = cgram(cmk, data);
        // Derive PIN codes
        byte[] pinmaterial = cgram(key, data);
        // Hexlify and numerify PIN material
        Map<String, String> pins = string2pins(hex2numbers(HexUtils.bin2hex(pinmaterial)));
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
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
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
