package secureDatagrams

import kotlinx.serialization.Serializable
import java.util.*

class RTSPPacket {
    @Serializable
    data class RequestAndCredentials(
        val configsB64: String,
        val n1: Int,
        val payloadB64: String,
        val payloadSignatureB64: String
    ) {
        @Serializable
        data class StreamConfig(
            val ip: String,
            val port: Int,
            val cipherSuite: String,
            val cryptoSA: String,
            val sessionKeyB64: String,
            val macKey: String,
            val nc: Int
        )

        val configBytes: ByteArray = Base64.getDecoder().decode(configsB64)
    }

    @Serializable
    data class Verification(val challengeB64: String) {
        data class Challenge(val na1: Int, val na2: Int, val ticketValidityConfirmation: Boolean)

        val challengeResponseBytes: ByteArray = Base64.getDecoder().decode(challengeB64)
    }

    @Serializable
    data class AckVerification(val challengeB64: String) {
        data class Challenge(val na2: Int, val na3: Int)

        val challengeResponseBytes: ByteArray = Base64.getDecoder().decode(challengeB64)
    }

    @Serializable
    data class SyncInitialFrame(val syncFrameB64: String) {
        data class FrameInfo(val na3: Int, val frameB64: String)

        val challengeResponseBytes: ByteArray = Base64.getDecoder().decode(syncFrameB64)
    }


    @Serializable
    data class EncryptedStreamData(val frameB64: String) {
        data class FrameInfo(val seqNum: Int, val frameB64: String)

        val challengeResponseBytes: ByteArray = Base64.getDecoder().decode(frameB64)
    }

    @Serializable
    data class SyncFinalFrame(val frameB64: String) {
        data class FrameInfo(val frameB64: String)

        val challengeResponseBytes: ByteArray = Base64.getDecoder().decode(frameB64)
    }


}