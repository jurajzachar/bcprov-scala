package com.blueskiron.crypto.utils.scala

import org.scalatest.FlatSpec
import org.scalatest.Matchers
import org.scalatest.prop.TableDrivenPropertyChecks.Table
import org.scalatest.prop.TableDrivenPropertyChecks.forAll

class CryptoSpec extends FlatSpec with Matchers {

  val multipliers = Table("*", 10, 100, 1000, 10000)

  val secretSize = 64

  val secret = SecretGenerator.generateSecret(secretSize)

  forAll(multipliers) { multiplier =>
    {
      //generate some payload
      val message = "this is a long secret message " * multiplier

      "AES-CTR encryption" should s"work for a valid symmetric key: $secret and message length: ${message.length}" in {
        val cipherText = Crypto.encryptAES(message, secret)
        val decrypted = Crypto.decryptAES(cipherText, secret)
        message shouldBe decrypted
      }
    }
  }

  "Digest of data" should "work" in {
    val foo = "This is a message"
    val digest1 = Crypto.digest(foo)
    val digest2 = Crypto.digest(foo)
    digest1 shouldBe digest2
  }

  "MAC digest of data" should "work" in {
    val foo = "This is a secret message"
    val key = SecretGenerator.generateSecret(32)
    val digest1 = Crypto.mac(foo, secret)
    val digest2 = Crypto.mac(foo, secret)
    digest1 shouldBe digest2
  }
  
}