package coins

import kotlinx.datetime.LocalDate
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.*


//private val json = Json { prettyPrint = true }

fun main() {
    val kpg: KeyPairGenerator = KeyPairGenerator.getInstance("EC")
    val ecsp = ECGenParameterSpec("secp256r1")
    kpg.initialize(ecsp)

    //TODO replace with bank key
    val bankKey = kpg.genKeyPair()
    val bankPrivKey = bankKey.private
    val bankPublicKey = bankKey.public
    val shaDigest = MessageDigest.getInstance("SHA-256")
    val sha3Digest = MessageDigest.getInstance("SHA3-256")


    val coinList: MutableList<Coin> = LinkedList<Coin>()
    for (i in 1..10) {
        val kp = kpg.genKeyPair()
        val privKey = kp.private
        val pubKey = kp.public
        val uuid = UUID.randomUUID().toString()
        val header = Coin.Header(uuid, "BinShilingCentralBank", 10, LocalDate(2030, 1, 1))
        val dsa: Signature = Signature.getInstance("SHA1withECDSA")
        dsa.initSign(privKey)
        dsa.update(Json.encodeToString(header).encodeToByteArray())
        val authHeader = Coin.AuthenticityHeader(header, pubKey.encoded, dsa.sign())
        dsa.initSign(bankPrivKey)
        dsa.update(Json.encodeToString(authHeader).encodeToByteArray())
        val issuerHeader = Coin.IssuerHeader(authHeader, dsa.sign(),bankPublicKey.encoded)

        val issuerHeaderJson = Json.encodeToString(issuerHeader).encodeToByteArray()
        val hc = Coin(issuerHeader, shaDigest.digest(issuerHeaderJson), sha3Digest.digest(issuerHeaderJson))
        coinList.add(hc)
        println(Json.encodeToString(hc))
    }
    File("config/proxy/coins.json").writeText(Json.encodeToString(coinList))
    File("config/signal/bankkey.json").writeBytes(bankPublicKey.encoded)
    println(Json.encodeToString(coinList))

}

