package coins

import kotlinx.datetime.LocalDate
import kotlinx.serialization.Serializable
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
    val ecsp: ECGenParameterSpec = ECGenParameterSpec("secp256r1")
    kpg.initialize(ecsp)

    //TODO replace with bank key
    val bankKey = kpg.genKeyPair()
    val bankPrivKey = bankKey.private
    val bankPublicKey = bankKey.public
    val shaDigest = MessageDigest.getInstance("SHA-256")
    val sha3Digest = MessageDigest.getInstance("SHA3-256")


    val coinList: MutableList<HelperCoin> = LinkedList<HelperCoin>()
    for (i in 1..10) {
        val kp = kpg.genKeyPair()
        val privKey = kp.private
        val pubKey = kp.public
        val uuid = UUID.randomUUID().toString()
        val header = HelperCoin.Header(uuid, "BinShilingCentralBank", 10, LocalDate(2030, 1, 1))
        val dsa: Signature = Signature.getInstance("SHA1withECDSA")
        dsa.initSign(privKey)
        dsa.update(Json.encodeToString(header).encodeToByteArray())
        val authHeader = HelperCoin.AuthenticityHeader(header, pubKey.encoded, dsa.sign())
        dsa.initSign(bankPrivKey)
        dsa.update(Json.encodeToString(authHeader).encodeToByteArray())
        val issuerHeader = HelperCoin.IssuerHeader(authHeader, bankPublicKey.encoded, dsa.sign())

        val issuerHeaderJson = Json.encodeToString(issuerHeader).encodeToByteArray()
        val hc = HelperCoin(issuerHeader, shaDigest.digest(issuerHeaderJson), sha3Digest.digest(issuerHeaderJson))
        coinList.add(hc)
        println(Json.encodeToString(hc))
    }
    File("coins.coin").writeText(Json.encodeToString(coinList))
    println(Json.encodeToString(coinList))

}

@Serializable
data class HelperCoin(
    val issuerHeader: IssuerHeader,
    val IntegrityProof1: ByteArray,
    val IntegrityProof2: ByteArray
) {
    @Serializable
    data class Header(
        val coinId: String,
        val coinIssuer: String,
        val value: Int,
        val expireDate: LocalDate,
    )

    @Serializable
    data class AuthenticityHeader(
        val header: Header,
        val coinPubKey: ByteArray,
        val coinAuthenticity: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as AuthenticityHeader

            if (header != other.header) return false
            if (!coinPubKey.contentEquals(other.coinPubKey)) return false
            if (!coinAuthenticity.contentEquals(other.coinAuthenticity)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = header.hashCode()
            result = 31 * result + coinPubKey.contentHashCode()
            result = 31 * result + coinAuthenticity.contentHashCode()
            return result
        }
    }

    @Serializable
    data class IssuerHeader(
        val authHeader: AuthenticityHeader,
        val issuerSignature: ByteArray,
        val issuerPublicKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as IssuerHeader

            if (authHeader != other.authHeader) return false
            if (!issuerSignature.contentEquals(other.issuerSignature)) return false
            if (!issuerPublicKey.contentEquals(other.issuerPublicKey)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = authHeader.hashCode()
            result = 31 * result + issuerSignature.contentHashCode()
            result = 31 * result + issuerPublicKey.contentHashCode()
            return result
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HelperCoin

        if (issuerHeader != other.issuerHeader) return false
        if (!IntegrityProof1.contentEquals(other.IntegrityProof1)) return false
        if (!IntegrityProof2.contentEquals(other.IntegrityProof2)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuerHeader.hashCode()
        result = 31 * result + IntegrityProof1.contentHashCode()
        result = 31 * result + IntegrityProof2.contentHashCode()
        return result
    }
}