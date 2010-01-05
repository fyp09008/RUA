/**
 * aid = 285921800099
 */
package hk.hku.cs.rua;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public class RSASign extends Applet {
	
	public static final byte RSA_CLASS = (byte) 0x13;
	
	public static final byte INS_PRI_KEY_INIT = 0x01;

	public static final byte INS_MOD_INIT = 0x02;
	
	public static final byte INS_PUB_KEY_INIT = 0x03;
	
	public static final byte INS_SIGN = 0x04;

	public static final byte INS_UNSIGN = 0x05;

	private RSAPrivateKey privateKey;
	
	private RSAPublicKey publicKey;
	
	private Cipher RSACipher;
	
	byte[] outbuf;
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new RSASign(bArray, bOffset, bLength);
	}

	private RSASign(byte[] bArray, short bOffset, byte bLength) {
		privateKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
		publicKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
		RSACipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		outbuf = new byte[128];
		register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	
	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		if (buf[ISO7816.OFFSET_CLA] != RSA_CLASS) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0x00:
			break;
		case (byte) INS_PRI_KEY_INIT:
			setPrivateKey(buf);
			break;
		case (byte) INS_MOD_INIT:
			setModulus(buf);
			break;
		case (byte) INS_PUB_KEY_INIT:
			setPublicKey(buf);
			break;
		case (byte) INS_SIGN:
			sign(apdu);
			break;
		case (byte) INS_UNSIGN:
			unsign(apdu);
			break;
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private void setPrivateKey(byte[] buf) {
		privateKey.setExponent(buf, (short) ISO7816.OFFSET_CDATA, (short) (buf[ISO7816.OFFSET_LC] & 0x00FF));
	}
	
	private void setModulus(byte[] buf) {
		privateKey.setModulus(buf, (short) ISO7816.OFFSET_CDATA, (short) (buf[ISO7816.OFFSET_LC] & 0x00FF));
		publicKey.setModulus(buf, (short) ISO7816.OFFSET_CDATA, (short) (buf[ISO7816.OFFSET_LC] & 0x00FF));
	}
	
	private void setPublicKey(byte[] buf) {
		publicKey.setExponent(buf, (short) ISO7816.OFFSET_CDATA, (short) (buf[ISO7816.OFFSET_LC] & 0x00FF));
	}
	
	
	private void sign(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		short plainTextLen = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
		apdu.setIncomingAndReceive();
		
		RSACipher.init(privateKey, Cipher.MODE_ENCRYPT);
		
		short ciphertextLen = RSACipher.doFinal(buf, (short) ISO7816.OFFSET_CDATA, plainTextLen, outbuf, (short) 0);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) ciphertextLen);
		apdu.sendBytesLong(outbuf, (short) 0, (short) ciphertextLen);
	}
	
	private void unsign(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		short ciphertextLen = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
		apdu.setIncomingAndReceive();
		
		RSACipher.init(publicKey, Cipher.MODE_DECRYPT);
		
		short plaintextLen = RSACipher.doFinal(buf, (short) ISO7816.OFFSET_CDATA, ciphertextLen, outbuf, (short) 0);
		apdu.setOutgoing();
		apdu.setOutgoingLength((short) plaintextLen);
		apdu.sendBytesLong(outbuf, (short) 0, (short) plaintextLen);
	}

}
