package com.blueskiron.crypto.utils.scala

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest
import java.util.Base64
import java.security.SecureRandom
import javax.crypto.spec.PBEKeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import java.util.Arrays

object Crypto {

  private val lineSeparator = System.getProperty("line.separator")

  /**
   * Creates ScretKey from provided secret, salt, number of iterations and key length
   */
  private def createKey(secret: String, salt: Array[Byte], iterations: Int, length: Int) = {
    val keySpec = new PBEKeySpec(secret.toCharArray(), salt, iterations, length)
    val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
    secretKeyFactory.generateSecret(keySpec).getEncoded();
  }

  /**
   * Encrypts given payload using AES-CRT with no padding and HMAC verification using provided secret.
   */
  def encryptAES(payload: String, secret: String) = {
    val random = SecureRandom.getInstance("SHA1PRNG");

    // Generate 160 bit Salt for Encryption Key
    val encSalt = new Array[Byte](20)
    random.nextBytes(encSalt)
    val key = createKey(secret, encSalt, 100000, 128)

    //encrypt
    val encKeySpec = new SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/CTR/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, encKeySpec, new IvParameterSpec(new Array[Byte](16)));
    val encryptedPayload = cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8))

    // Generate 160 bit Salt for HMAC Key
    val hmacSalt = new Array[Byte](20)
    random.nextBytes(hmacSalt)
    // Generate 160 bit HMAC Key
    val hmacKey = createKey(secret, hmacSalt, 100000, 160)

    //Perform HMAC using SHA-256
    val hmacKeySpec = new SecretKeySpec(hmacKey, "HmacSHA256")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(hmacKeySpec)
    val hmac = mac.doFinal(encryptedPayload)

    //Construct Output as "ESALT + HSALT + CIPHERTEXT + HMAC"
    def encLen = encryptedPayload.length
    val finalLen = 40 + encLen + 32
    val out = new Array[Byte](finalLen)
    System.arraycopy(encSalt, 0, out, 0, 20);
    System.arraycopy(hmacSalt, 0, out, 20, 20);
    System.arraycopy(encryptedPayload, 0, out, 40, encLen);
    System.arraycopy(hmac, 0, out, 40 + encLen, 32);

    // Return a Base64 Encoded String
    new String(Base64.getEncoder().encode(out))
  }

  /**
   * Decrypts given payload using AES-CRT with no padding and HMAC verification using provided secret.
   */
  def decryptAES(payload: String, secret: String) = {
    val in = Base64.getDecoder().decode(payload);
    // Check Minimum Length (ESALT (20) + HSALT (20) + HMAC (32))
    require(in.length > 72)
    // Recover Elements from String
    val encSalt = Arrays.copyOfRange(in, 0, 20);
    val hmacSalt = Arrays.copyOfRange(in, 20, 40);
    val encryptedPayload = Arrays.copyOfRange(in, 40, in.length - 32);
    val hmac = Arrays.copyOfRange(in, in.length - 32, in.length);

    // Regenerate HMAC key using Recovered Salt (hsalt)
    val hmacKey = createKey(secret, hmacSalt, 100000, 160)
    val hmacKeySpec = new SecretKeySpec(hmacKey, "HmacSHA256")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(hmacKeySpec)
    val computedHmac = mac.doFinal(encryptedPayload)

    // Compare Computed HMAC vs Recovered HMAC
    if (!MessageDigest.isEqual(hmac, computedHmac)) {
      throw new Exception("Recovered and computed hash not identical, aborting!")
    } else {
      // HMAC Verification Passed
      // Regenerate Encryption Key using Recovered Salt (esalt)
      val key = createKey(secret, encSalt, 100000, 128)

      // Perform Decryption
      val encKeySpec = new SecretKeySpec(key, "AES")
      val cipher = Cipher.getInstance("AES/CTR/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, encKeySpec, new IvParameterSpec(new Array[Byte](16)));
      val out = cipher.doFinal(encryptedPayload)

      // Return our Decrypted String
      new String(out, StandardCharsets.UTF_8);
    }
  }

  /**
   * Constant time equals method.
   *
   * Given a length that both Strings are equal to, this method will always run in constant time.  This prevents
   * timing attacks.
   */
  def constantTimeEquals(a: String, b: String): Boolean = {
    if (a.length != b.length) {
      false
    } else {
      var equal = 0
      for (i <- 0 until a.length) {
        equal |= a(i) ^ b(i)
      }
      equal == 0
    }
  }

  def mac(text: String, secret: String) = {
    val hmacKey = createKey(secret, new Array[Byte](10), 100000, 160)
    val hmacKeySpec = new SecretKeySpec(hmacKey, "HmacSHA512")
    val mac = Mac.getInstance("HmacSHA512")
    mac.init(hmacKeySpec)
    val payload = normalizeLineSeparator(text).getBytes(StandardCharsets.UTF_8)
    new String(Base64.getEncoder.encode(mac.doFinal(payload)))
  }
  /**
   * @param text
   * @return
   */
  def digest(text: String): String = {
    digest(normalizeLineSeparator(text).getBytes(StandardCharsets.UTF_8))
  }

  private def digest(bytes: Array[Byte]): String = digest(bytes, MessageDigest.getInstance("SHA-512"))

  private def digest(bytes: Array[Byte], md: MessageDigest): String = {
    md.update(bytes)
    new String(Base64.getEncoder.encode(md.digest()))
  }

  private def normalizeLineSeparator(text: String): String = text.replaceAll(lineSeparator, "\n")
}