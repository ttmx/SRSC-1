package sadkdp.dto

import kotlinx.serialization.Serializable
import secureDatagrams.Settings

@Serializable
data class TicketCredentialsDto(
    val proxyPayload: ByteArray,
    val proxySignature: ByteArray,
    val streamingPayload: ByteArray,
    val streamingSignature: ByteArray
) {
    @Serializable
    data class Payload(
        val ip: String, val port: Int, val movieId: String,
        val settings: Settings, val nc: Int
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TicketCredentialsDto

        if (!proxyPayload.contentEquals(other.proxyPayload)) return false
        if (!proxySignature.contentEquals(other.proxySignature)) return false
        if (!streamingPayload.contentEquals(other.streamingPayload)) return false
        if (!streamingSignature.contentEquals(other.streamingSignature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = proxyPayload.contentHashCode()
        result = 31 * result + proxySignature.contentHashCode()
        result = 31 * result + streamingPayload.contentHashCode()
        result = 31 * result + streamingSignature.contentHashCode()
        return result
    }
}
