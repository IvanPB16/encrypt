package com.test;

import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.marvec.encryptor.util.EncryptionException;

public class AesEncryption {
  Map<String, String> initParams;
  String key, iv;
  String mode, encoding;
  String keyFile;
  String ENCODING = "ISO-8859-1";

  public AesEncryption() {
    Security.addProvider(new BouncyCastleProvider());
  }

  /* PARAMETERS INITIALITATION */
  public void setInitParams() {
    // initParams=params;
    key = "3e62978a1d6f393555dbecd3fb17b8fe";
    iv = "9f900fc926865506cace52cc9f36249f";
    mode = "AES/CBC/PKCS7Padding";
    encoding = "HEX";
    if (encoding.equalsIgnoreCase("BASE64") && encoding.equalsIgnoreCase("HEX"))
      throw new IllegalArgumentException("AES.ENCODING can only be 'HEX' of 'BASE64'");
  }

  /* INFORMATION CIPHERING @return encodeBase24 **/
  public String encrypt(String data) throws EncryptionException {
    byte[] output = null;
    try {
      byte[] keyBytes = decode(key);
      byte[] input = data.getBytes(ENCODING);

      AlgorithmParameterSpec ivSpec = new IvParameterSpec(Hex.decodeHex(iv.toCharArray()));

      SecretKeySpec keySpec = null;
      keySpec = new SecretKeySpec(keyBytes, "AES");
      Cipher cipher = Cipher.getInstance(mode);
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
      output = cipher.doFinal(input);
    } catch (Exception e) {
      throw new EncryptionException("Error", e);
    }
    return encode(output);
  }

  /* INFORMATION ENCODE */
  private String encode(byte[] output) {
    if (mode.equalsIgnoreCase("BASE64"))
      return Base64.encodeBase64String(output);
    else
      return new String(Hex.encodeHex(output));
  }

  /* INFORMATION DECIPHERING @return String */
  public String decrypt(String data) throws EncryptionException {
    byte[] output = null;
    try {
      byte[] keyBytes = decode(key);
      byte[] input = decode(data);
      SecretKeySpec keySpec = null;
      keySpec = new SecretKeySpec(keyBytes, "AES");
      Cipher cipher = Cipher.getInstance(mode);
      AlgorithmParameterSpec ivSpec = new IvParameterSpec(Hex.decodeHex(iv.toCharArray()));
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
      output = cipher.doFinal(input);
    } catch (Exception e) {
      System.out.println(e);
      throw new EncryptionException("Error", e);
    }
    return new String(output);
  }

  /* INFORMATION DECODE */
  private byte[] decode(String data) throws DecoderException {
    if (data.indexOf("=") > 0 || data.indexOf("+") > 0)
      return Base64.decodeBase64(data);
    else
      return Hex.decodeHex(data.toCharArray());
  }

}
