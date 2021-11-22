package secureDatagrams

import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.util.*


class SADKDPPacket {

    @Serializable
    data class Authentication(val challengeB64: String) {
        @Serializable
        data class Challenge(val n1: Int, val n2: Int, val movieId: String)

        val challengeBytes: ByteArray = Base64.getDecoder().decode(challengeB64)
    }

    data class PaymentRequest(val chalResponseB64: String, val signatureB64: String) {
        @Serializable
        data class ChallResponse(val price: Float, val n2: Int, val n3: Int)

        val challengeResponse: ChallResponse =
            Json.decodeFromString(Base64.getDecoder().decode(chalResponseB64).toString())

        init {
            CryptoTools.checkSignature(chalResponseB64, signatureB64)
        }
    }

    data class Payment(val signedChalResponseB64: String, val signatureB64: String) {
        @Serializable
        data class ChallResponse(val price: Float, val n2: Int, val n3: Int)

        init {
            CryptoTools.checkSignature(signedChalResponseB64, signatureB64)
        }
    }

    data class TicketCredentials(
        val encryptedB64: String,
        val toForwardB64: String,
        val signatureB64: String
    )
}