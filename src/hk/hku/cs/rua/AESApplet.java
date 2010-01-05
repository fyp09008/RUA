/**
 * aid = 285921800004
 */
package hk.hku.cs.rua;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

public class AESApplet extends Applet {
	public static final byte AES_CLASS = (byte) 0x11;

	public static final byte INS_KEY_INIT = 0x01;

	public static final byte INS_KEY_RETURN = 0x02;

	public static final byte INS_ENCRYPT = 0x03;

	public static final byte INS_DECRYPT = 0x04;

	public static final byte INS_RE_ENCRYPT = 0x05;

	final static byte KEY_TYPE = KeyBuilder.TYPE_AES;

	final static short KEY_LENGTH_BITS = KeyBuilder.LENGTH_AES_128;

	final static short KEY_LENGTH = (short) (KEY_LENGTH_BITS / (short) 8);

	private AESKey key_encrypt;

	private AESKey key_decrypt;

	private Cipher cipher;
	
	byte[] outBuff;

	public AESApplet() {
		outBuff = new byte[128];
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new AESApplet()
				.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		if (buf[ISO7816.OFFSET_CLA] != AES_CLASS) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) INS_KEY_INIT:
			initAESKey(buf);
			break;
		case (byte) INS_ENCRYPT:
			encrypt(apdu);
			break;
		case (byte) INS_DECRYPT:
			decrypt(apdu);
			break;
		case (byte) INS_KEY_RETURN:
			keyReturn();
			break;
		case (byte) INS_RE_ENCRYPT:
			reEncrypt(apdu);
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void initAESKey(byte[] buf) {
		cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		try {

			switch (buf[ISO7816.OFFSET_P1]) {
			case 0x01:
				key_encrypt = (AESKey) KeyBuilder.buildKey(KEY_TYPE,
						KEY_LENGTH_BITS, false);
				key_encrypt.setKey(buf, ISO7816.OFFSET_CDATA);

				break;
			case 0x02:
				key_decrypt = (AESKey) KeyBuilder.buildKey(KEY_TYPE,
						KEY_LENGTH_BITS, false);
				key_decrypt.setKey(buf, ISO7816.OFFSET_CDATA);

				break;
			}
		} catch (CryptoException e) {
			if (e.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
				ISOException
						.throwIt((short) (0x1100 | CryptoException.NO_SUCH_ALGORITHM));
			}
		}
	}

	private void encrypt(APDU apdu) {
		cipher.init(key_encrypt, Cipher.MODE_ENCRYPT);

		byte[] buffer = apdu.getBuffer();
		byte numBytes = buffer[ISO7816.OFFSET_LC];
		apdu.setIncomingAndReceive();

		short outLen = cipher.doFinal(buffer, (short) ISO7816.OFFSET_CDATA,
				numBytes, outBuff, (short) 0);

		apdu.setOutgoing();
		apdu.setOutgoingLength(outLen);
		apdu.sendBytesLong(outBuff, (short) 0, outLen);
	}

	private void decrypt(APDU apdu) {
		cipher.init(key_decrypt, Cipher.MODE_DECRYPT);

		byte[] buffer = apdu.getBuffer();
		byte numBytes = buffer[ISO7816.OFFSET_LC];
		apdu.setIncomingAndReceive();

		short outLen = cipher.doFinal(buffer, (short) ISO7816.OFFSET_CDATA,
				numBytes, outBuff, (short) 0);

		apdu.setOutgoing();
		apdu.setOutgoingLength(outLen);
		apdu.sendBytesLong(outBuff, (short) 0, outLen);

	}

	private void keyReturn() {
		// byte[] keyData = new byte[key.getSize()];
		// key.getKey(keyData, (short) 0);
	}

	private void reEncrypt(APDU apdu) {
		// Decrypt
		cipher.init(key_decrypt, Cipher.MODE_DECRYPT);

		byte[] buffer = apdu.getBuffer();
		byte numBytes = buffer[ISO7816.OFFSET_LC];
		apdu.setIncomingAndReceive();

		try {
			byte[] tmp = JCSystem.makeTransientByteArray(numBytes,
					JCSystem.CLEAR_ON_RESET);

			short outLen = cipher.doFinal(buffer, (short) ISO7816.OFFSET_CDATA,
					numBytes, tmp, (short) 0);

			// Encrypt
			cipher.init(key_encrypt, Cipher.MODE_ENCRYPT);

			outLen = cipher.doFinal(tmp, (short) (short) 0, numBytes, outBuff,
					(short) 0);

			tmp = null;

			// Request deletion service of the Java Card runtime environment
			JCSystem.requestObjectDeletion();

			apdu.setOutgoing();
			apdu.setOutgoingLength(outLen);
			apdu.sendBytesLong(outBuff, (short) 0, outLen);

		} catch (SystemException e) {
			if (e.getReason() == SystemException.NO_TRANSIENT_SPACE) {
				ISOException
						.throwIt((short) (0x1100 | SystemException.NO_TRANSIENT_SPACE));
			} else {
				ISOException.throwIt(e.getReason());
			}
		}
	}
}

