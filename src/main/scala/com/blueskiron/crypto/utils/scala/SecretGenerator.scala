package com.blueskiron.crypto.utils.scala

import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import javax.crypto.KeyGenerator

object SecretGenerator {

  private lazy val random = new java.security.SecureRandom()

  private val defaultChars =
      "?>=<;:/.-,+*)('&%$#\"!" +
      "abcdefghijklmnopqrstuvwxyz" +
      "0123456789" +
      "ZYXWVUTSRQPONMLKJIHGFEDCBA" +
      "[\\]^_@{|}~"

  def randomString(alphabet: String)(n: Int): String =
    Stream.continually(random.nextInt(alphabet.size)).map(alphabet).take(n).mkString

  def generateSecret(size: Int) = {
    randomString(defaultChars)(size)
  }

}