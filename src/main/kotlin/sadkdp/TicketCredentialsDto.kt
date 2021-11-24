package sadkdp

import kotlinx.serialization.Serializable
import secureDatagrams.Settings

@Serializable
data class TicketCredentialsDto(val payload: Payload, val signature: ByteArray) {
    @Serializable
    data class Payload(val proxyPayload: ByteArray, val streamingPayload: ByteArray) {
        @Serializable
        data class Content(
            val ip: String, val port: Int, val movieId: String,
            val settings: Settings, val nc: Int
        )

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Payload

            if (!proxyPayload.contentEquals(other.proxyPayload)) return false
            if (!streamingPayload.contentEquals(other.streamingPayload)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = proxyPayload.contentHashCode()
            result = 31 * result + streamingPayload.contentHashCode()
            return result
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TicketCredentialsDto

        if (payload != other.payload) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = payload.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

}
