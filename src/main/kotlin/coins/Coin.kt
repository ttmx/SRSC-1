package coins

import kotlinx.datetime.LocalDate
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import secureDatagrams.CryptoTools
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECPublicKeySpec
import java.security.spec.X509EncodedKeySpec


@Serializable
data class Coin(
    val issuerHeader: IssuerHeader,
    val IntegrityProof1: ByteArray,
    val IntegrityProof2: ByteArray
) {
    companion object {
        private val shaDigest: MessageDigest = MessageDigest.getInstance("SHA-256")
        private val sha3Digest: MessageDigest = MessageDigest.getInstance("SHA3-256")

        private val dsa: Signature = Signature.getInstance("SHA1withECDSA")
        var keyFactory: KeyFactory = KeyFactory.getInstance("EC")
    }

    val coinId
        get() = issuerHeader.authHeader.header.coinId

    val coinIssuer
        get() = issuerHeader.authHeader.header.coinIssuer

    val value
        get() = issuerHeader.authHeader.header.value

    fun verifySignature() {
        var toCheck = Json.encodeToString(issuerHeader).encodeToByteArray()
        CryptoTools.checkHash(shaDigest, toCheck, IntegrityProof1)
        CryptoTools.checkHash(sha3Digest, toCheck, IntegrityProof2)


        var pubKey: PublicKey = keyFactory.generatePublic(X509EncodedKeySpec(issuerHeader.issuerPublicKey))
        toCheck = Json.encodeToString(issuerHeader.authHeader).encodeToByteArray()

        dsa.initVerify(pubKey)
        dsa.update(toCheck)
        dsa.verify(issuerHeader.issuerSignature)


        pubKey = keyFactory.generatePublic(ECPublicKeySpec(issuerHeader.authHeader.coinPubKey))

        toCheck = Json.encodeToString(issuerHeader.authHeader.header).encodeToByteArray()

        dsa.initVerify(pubKey)
        dsa.update(toCheck)
        dsa.verify(issuerHeader.authHeader.coinAuthenticity)
    }

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

        other as Coin

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