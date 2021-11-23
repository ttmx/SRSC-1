package secureDatagrams

import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.util.*


class SADKDPPacket {

    @Serializable
    data class Authentication(val challengeBytes: ByteArray) {
        @Serializable
        data class Challenge(val n1: Int, val n2: Int, val movieId: String)

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Authentication

            if (!challengeBytes.contentEquals(other.challengeBytes)) return false

            return true
        }

        override fun hashCode(): Int {
            return challengeBytes.contentHashCode()
        }

//        val challengeBytes: ByteArray = Base64.getDecoder().decode(challengeB64)
    }

    data class PaymentRequest(val challengeResponse: ByteArray, val signature: ByteArray) {
        @Serializable
        data class ChallResponse(val price: Float, val n2: Int, val n3: Int)


        init {
//            CryptoTools.checkSignature(chalResponseB64, signatureB64)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as PaymentRequest

            if (!challengeResponse.contentEquals(other.challengeResponse)) return false
            if (!signature.contentEquals(other.signature)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = challengeResponse.contentHashCode()
            result = 31 * result + signature.contentHashCode()
            return result
        }
    }

    data class Payment(val signedChalResponse: ByteArray, val signature: ByteArray) {
        @Serializable
        data class ChallResponse(val price: Float, val n2: Int, val n3: Int)

        init {
//            CryptoTools.checkSignature(signedChalResponseB64, signatureB64)
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Payment

            if (!signedChalResponse.contentEquals(other.signedChalResponse)) return false
            if (!signature.contentEquals(other.signature)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = signedChalResponse.contentHashCode()
            result = 31 * result + signature.contentHashCode()
            return result
        }
    }

    data class TicketCredentials(
        val encryptedB64: String,
        val toForwardB64: String,
        val signatureB64: String
    )
}