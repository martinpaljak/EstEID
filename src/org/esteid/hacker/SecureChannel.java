/**
 * Copyright (c) 2014-2016 Martin Paljak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.esteid.hacker;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import apdu4j.HexUtils;

// Implements SecureChannel as described in EstEID specs
public final class SecureChannel {
	private static Logger logger = LoggerFactory.getLogger(SecureChannel.class);

	private static IvParameterSpec nulliv = new IvParameterSpec(new byte[8]);

	// the session keys, in a handy package
	public class SessionState {
		boolean authenticated = false;
		public byte[] SK1, SK2, SSC; // FIXME: too broad access 
		@Override
		public String toString() { return "SK1: " + HexUtils.bin2hex(SK1) + "\nSK2: " + HexUtils.bin2hex(SK2) + "\nSSC: " + HexUtils.bin2hex(SSC);}
	}


	@SuppressWarnings("serial")
	public static class SecureChannelException extends Exception {
		public SecureChannelException(String message, Throwable reason) {
			super(message, reason);
		}

		public SecureChannelException(String message) {
			super(message);
		}
	} 

	private CardChannel channel;
	private SessionState state;
	private SecureChannel(CardChannel channel) {
		this.channel = channel;
	}

	public static SecureChannel getInstance(CardChannel c) {
		return new SecureChannel(c);
	}

	public void mutualAuthenticate(byte[] cmk, int cmkNumber) throws CardException, SecureChannelException  {
		try {
			SessionState state = new SessionState();
			SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
			logger.trace("MUTUAL AUTHENTICATE with CMK #{}", cmkNumber);
			logger.trace("CMK: {}", HexUtils.bin2hex(cmk));


			// Get RND.IFD from card with GET CHALLENGE
			ResponseAPDU response = channel.transmit(new CommandAPDU(HexUtils.hex2bin("0084000000")));
			if (response.getSW() != 0x9000) {
				throw new SecureChannelException("Could not get challenge from card: " + response.getSW());
			}
			byte[] RNDICC = response.getData();
			logger.trace("RND.ICC: {}", HexUtils.bin2hex(RNDICC));

			// Generate local random values
			// K.IFD
			byte[] KIFD = new byte[0x20];
			rnd.nextBytes(KIFD);

			// RND.IFD
			byte[] RNDIFD = new byte[0x08];
			rnd.nextBytes(RNDIFD);
			logger.trace("RND.IFD: {}", HexUtils.bin2hex(RNDIFD));

			// Construct the APDU block.
			byte[] payload = new byte[0x30];
			System.arraycopy(RNDIFD, 0, payload, 0, RNDIFD.length);
			System.arraycopy(RNDICC, 0, payload, RNDIFD.length, RNDICC.length);
			System.arraycopy(KIFD, 0, payload, RNDIFD.length + RNDICC.length, KIFD.length);

			// Encrypt
			SecretKeySpec keyspec = new SecretKeySpec(cmk, "DESede");
			// MUTUAL AUTHENTICATE always uses ICV == 0
			Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, keyspec, nulliv);

			byte[] cgram = cipher.doFinal(payload);

			logger.trace("Payload: {}", HexUtils.bin2hex(payload));
			logger.trace("Crypted: {}", HexUtils.bin2hex(cgram));

			CommandAPDU authAPDU = new CommandAPDU(0x00, 0x82, 0x00, cmkNumber, cgram, 0x30);
			response = channel.transmit(authAPDU);
			if (response.getSW() != 0x9000) {
				throw new SecureChannelException("MUTUAL AUTHENTICATE: " + Integer.toHexString(response.getSW()));
			}


			// Decrypt response
			cipher.init(Cipher.DECRYPT_MODE, keyspec, nulliv);
			byte[] keys = cipher.doFinal(response.getData());
			logger.trace("Encrypted: {}", HexUtils.bin2hex(response.getData()));
			logger.trace("Decrypted: {}", HexUtils.bin2hex(keys));

			// Check random
			byte RNDIFDCHECK[] = new byte[8];
			System.arraycopy(keys, 8, RNDIFDCHECK, 0, 8);
			// "secret" is random, so timing is no important.
			if (!Arrays.equals(RNDIFD, RNDIFDCHECK)) {
				logger.warn("RNDIFD did not match! {} vs {}", HexUtils.bin2hex(RNDIFD), HexUtils.bin2hex(RNDIFDCHECK));
				throw new SecureChannelException("RNDIFD do not match");
			}

			// XOR session key block.
			byte[] KICC = Arrays.copyOfRange(keys, 0x10, 0x30);
			logger.trace("K.ICC: {}", HexUtils.bin2hex(KICC));
			logger.trace("K.IFD: {}", HexUtils.bin2hex(KIFD));
			byte[] KXOR = Arrays.copyOf(KICC, KICC.length);

			// Derive Session keys with K.IFD XOR K.ICC
			for (int i = 0; i < 0x20; i++) {
				KXOR[i] ^= KIFD[i];
			}
			logger.trace("K.XOR: {}", HexUtils.bin2hex(KXOR));

			// Now set SK1, SK2 and SSC
			state.SK1 = Arrays.copyOfRange(KXOR, 0x00, 0x10);
			state.SK2 = Arrays.copyOfRange(KXOR, 0x10, 0x20);

			state.SSC = new byte[8];
			System.arraycopy(keys, 12, state.SSC, 0, 4);
			System.arraycopy(keys, 4, state.SSC, 4, 4);

			enforceOddBitcount(state.SK1, (short) 0, (short) state.SK1.length);
			enforceOddBitcount(state.SK2, (short) 0, (short) state.SK2.length);
			logger.trace("Session keys: {}", state.toString());
			state.authenticated = true;
			this.state = state;
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			// Must be configured properly
			throw new RuntimeException("BC not correctly configured?", e);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException |IllegalBlockSizeException | BadPaddingException e) {
			// Generic crypto exception, must be logged
			throw new SecureChannelException("Failed mutual authentication", e);
		} 
	}



	private static CommandAPDU wrap(SessionState state, CommandAPDU apdu) throws SecureChannelException {
		try {
			// Increase SSC
			buffer_increment(state.SSC);

			// Make sure that the input CLA is correct
			int cla = apdu.getCLA() | 0x0C;

			byte[] payload = new byte[0];
			// Encrypt payload, if present
			if (apdu.getData().length > 0) {
				// Encrypt it with SK1, IV=SSC
				SecretKeySpec keyspec = new SecretKeySpec(state.SK1, "DESede");
				Cipher cipher = Cipher.getInstance("DESede/CBC/ISO7816-4Padding", "BC");

				cipher.init(Cipher.ENCRYPT_MODE, keyspec, new IvParameterSpec(state.SSC));

				byte[] cryptedPayload = cipher.doFinal(apdu.getData());
				payload = new byte[cryptedPayload.length + 3];
				payload[0] = (byte) 0x87; // Payload type tag
				payload[1] = (byte) (cryptedPayload.length + 1); // length of payload // TODO: bigger chunks
				payload[2] = 0x01; // Content indicator + content
				System.arraycopy(cryptedPayload, 0, payload, 3, cryptedPayload.length);
				logger.trace("Original APDU: {}", HexUtils.bin2hex(apdu.getBytes()));
				logger.trace("APDU  payload: {}", HexUtils.bin2hex(apdu.getData()));
				logger.trace("Crypt payload: {}", HexUtils.bin2hex(payload));

				// Verify.
				Cipher dec = Cipher.getInstance("DESede/CBC/NoPadding", "BC");
				dec.init(Cipher.DECRYPT_MODE, keyspec, new IvParameterSpec(state.SSC));
				logger.trace("Verified APDU: {}", HexUtils.bin2hex(dec.doFinal(cryptedPayload)));
			}

			// Calculate MAC
			byte[] macBuffer = new byte[8 + payload.length];
			// Extend and pad command header
			Arrays.fill(macBuffer, (byte) 0x00);
			macBuffer[0] = (byte) cla;
			macBuffer[1] = (byte) apdu.getINS();
			macBuffer[2] = (byte) apdu.getP1();
			macBuffer[3] = (byte) apdu.getP2();
			macBuffer[4] = (byte) 0x80;
			System.arraycopy(payload, 0, macBuffer, 8, payload.length);

			logger.trace("SSC+1: {}", HexUtils.bin2hex(state.SSC));

			Mac signer = Mac.getInstance("ISO9797ALG3WITHISO7816-4PADDING", "BC");
			signer.init(new SecretKeySpec(state.SK2, "DESede"), new IvParameterSpec(state.SSC));

			logger.trace("MAC payload: ({} bytes): {}", macBuffer.length, HexUtils.bin2hex(macBuffer));
			byte[] mac = signer.doFinal(macBuffer);
			logger.trace("MAC: {}", HexUtils.bin2hex(mac));

			// Construct final command
			byte[] apduBytes = new byte[payload.length + mac.length + 2];
			System.arraycopy(payload, 0, apduBytes, 0, payload.length);
			int offset = payload.length;
			apduBytes[offset++] = (byte) 0x8e;
			apduBytes[offset++] = (byte) 0x08; // mac.length
			System.arraycopy(mac, 0, apduBytes, offset, mac.length);

			// Always send Le as 0x00
			CommandAPDU cmd = new CommandAPDU(cla, apdu.getINS(), apdu.getP1(), apdu.getP2(), apduBytes, 256);
			logger.trace("Final APDU: {}", HexUtils.bin2hex(cmd.getBytes()));
			return cmd;
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			// Must be configured properly
			throw new RuntimeException("BC not correctly configured?", e);
		} catch (GeneralSecurityException e) {
			// Generic crypto exception, must be logged
			throw new SecureChannelException("Failed to wrap APDU", e);
		} 
	}

	private static ResponseAPDU unwrap(SessionState state, ResponseAPDU apdu) throws SecureChannelException {
		try {
			// Increment SSC
			buffer_increment(state.SSC);

			logger.trace("{}", state.toString());
			// Verify Mac
			Mac signer = Mac.getInstance("ISO9797ALG3WITHISO7816-4PADDING", "BC");
			signer.init(new SecretKeySpec(state.SK2, "DESede"), new IvParameterSpec(state.SSC));

			byte [] cardData = apdu.getData();

			// Card MAC is last 8 bytes FIXME: check header 8e 80
			byte [] cardMac = Arrays.copyOfRange(cardData, cardData.length - 8, cardData.length);
			logger.trace("Card MAC: " + HexUtils.bin2hex(cardMac));

			// Calculate MAC over all data except card MAC itself
			byte [] macData = Arrays.copyOf(cardData, cardData.length - 10);
			logger.trace("Response MAC payload: " + macData.length + " " + HexUtils.bin2hex(macData));

			byte [] mac = signer.doFinal(macData);
			logger.trace("Response MAC: " + HexUtils.bin2hex(mac));

			// Verify MAC
			if (!Arrays.equals(cardMac, mac))
				throw new SecureChannelException("MAC mismatch! " + HexUtils.bin2hex(cardMac) + " vs " + HexUtils.bin2hex(mac));

			if (cardData[0] == (byte)0x87) {
				// Decrypt
				SecretKeySpec keyspec = new SecretKeySpec(state.SK1, "DESede");
				Cipher cipher = Cipher.getInstance("DESede/CBC/ISO7816-4Padding", "BC");
				cipher.init(Cipher.DECRYPT_MODE, keyspec, new IvParameterSpec(state.SSC));
				// get length of payload
				int len = get_length(macData, 1);
				byte [] cgram = new byte[len];
				// 87 <len> 1 <data>
				System.arraycopy(macData, macData.length - len, cgram, 0, cgram.length);
				logger.trace("Data for decryption: " + HexUtils.bin2hex(cgram));

				byte [] datagram = cipher.doFinal(cgram);
				logger.trace("Decrypted data: " + HexUtils.bin2hex(datagram));

				// extend datagram for SW
				byte[] rapdu = Arrays.copyOf(datagram, datagram.length + 2);
				rapdu[datagram.length] = (byte) apdu.getSW1();
				rapdu[datagram.length+1] = (byte) apdu.getSW2();
				logger.trace("ResponseAPDU: " + HexUtils.bin2hex(rapdu));
				return new ResponseAPDU(rapdu);
			}

			if (cardData[0] == (byte)0x99)  { // SW only
				byte[] rapdu = new byte[2];
				// Extract the verified SW
				rapdu[0] = cardData[0x02];
				rapdu[1] = cardData[0x03];
				logger.trace("ResponseAPDU: " + HexUtils.bin2hex(rapdu));
				return new ResponseAPDU(rapdu);
			}
			return null;
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			// Must be configured properly
			throw new RuntimeException("BC not correctly configured?", e);
		} catch (GeneralSecurityException e) {
			// Generic crypto exception, must be logged
			throw new SecureChannelException("Failed to unwrap APDU", e);
		} 
	}

	// Takes care of tracking the state (increasing SSC)
	public ResponseAPDU transmit(CommandAPDU command) throws CardException, SecureChannelException {
		if (!state.authenticated)
			throw new IllegalStateException("No mutual authentication");
		CommandAPDU wrapped = wrap(state, command);
		ResponseAPDU response_wrapped = channel.transmit(wrapped);
		return unwrap(state, response_wrapped);
	} 

	public CardChannel getChannel() {
		return this.channel;
	}

	public SessionState getState() {
		return state;
	}

	private void enforceOddBitcount(byte[] buffer, short offset, short len) {
		short i = offset;
		for (i = offset; i < (short) (offset + len); i++) {
			byte bitcount = 0;
			// count set bits.
			for (short j = 0; j < 8; j++) {
				if (((byte) (buffer[i] >>> j) & (byte) 1) == (byte) 1) {
					bitcount++;
				}
			}

			if ((byte) (bitcount % 2) == 0) {
				buffer[i] ^= 1; // Set LSB
			}
		}
	}

	private static int get_length(byte[] data, int offset) {
		if ((data[offset] & 0xFF) == 0x82) {
			return ((data[offset+1] & 0xFF) << 8) | (data[offset+2] & 0xFF);
		} else if ((data[offset] & 0xFF) == 0x81) {
			return (data[offset+1] & 0xFF);
		} else if ((data[offset] & 0xFF) < 0x80) {
			return (data[offset] & 0xFF);
		}
		throw new RuntimeException("Bad L encoding in TLV at offset " + offset);
	}

	// Given a MSB byte array with a length, increment it by one.
	private static void buffer_increment(byte[] buffer) {
		if (buffer.length < 1)
			return;
		for (short i = (short) (buffer.length - 1); i >= 0; i--) {
			if (buffer[i] != (byte) 0xFF) {
				buffer[i]++;
				break;
			} else {
				buffer[i] = (byte) 0x00;
			}
		}
	}
}
