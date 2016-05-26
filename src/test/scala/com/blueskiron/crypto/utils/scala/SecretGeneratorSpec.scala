package com.blueskiron.crypto.utils.scala

import org.scalatest.FlatSpec
import org.scalatest.Matchers
import org.scalatest.prop.TableDrivenPropertyChecks._

class SecretKeyGeneratorSpec extends FlatSpec with Matchers {

  val rounds = Table("size", 10, 100, 1000, 10000, 100000)

  val secretSize = 32

  forAll(rounds) { round =>
    {
      "SecretGenerator" should s"generate $round unique 256-bit keys" in {
        val secrets = generateN(round, Nil)
        println(s"generated ${secrets.size} secrets")
        println(s"head: ${secrets.head}")
        secrets.toSet.size shouldBe round
      }
    }
  }

  private def generateN(n: Int, secrets: List[String]): List[String] = {
    if (n == 0) {
      secrets
    } else {
      generateN(n - 1, SecretGenerator.generateSecret(secretSize) :: secrets)
    }
  }
}