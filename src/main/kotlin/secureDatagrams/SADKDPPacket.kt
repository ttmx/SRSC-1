package secureDatagrams

import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*


class SADKDPPacket {


    data class Hello(val userId: String, val proxyBoxId: String)

    data class AuthenticationRequest(val n1: String, val salt: String, val counter: Int)

    @Serializable
    data class Authentication(val challengeB64: String, val intCheck: Int){
        @Serializable
        data class Challenge(val n1: String,val n2:String,val movieId:String)
        val challengeBytes:ByteArray = Base64.getDecoder().decode(challengeB64)
    }

    data class PaymentRequest(val chalResponseB64: String,val signatureB64:String, val intCheck: Int){
        @Serializable
        data class ChallResponse(val price:Float,val n2:Int,val n3:Int)
        val challengeResponse: ChallResponse = Json.decodeFromString(Base64.getDecoder().decode(chalResponseB64).toString())
        init {
            CryptoTools.checkSignature(chalResponseB64,signatureB64)
        }
    }

    data class Payment(val signedChalResponseB64: String,val signatureB64: String, val intCheck: Int){
        @Serializable
        data class ChallResponse(val price:Float,val n2:Int,val n3:Int)
        init {
            CryptoTools.checkSignature(signedChalResponseB64,signatureB64)
        }
    }

    data class TicketCredentials(
        val encryptedB64: String,
        val toForwardB64: String,
        val signatureB64: String,
        val intCheck: Int
    )
}