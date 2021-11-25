package rtstp.dto

import kotlinx.serialization.Serializable

@Serializable
data class RequestAndCredentialsDto(
    val streamingPayload: ByteArray,
    val streamingSignature: ByteArray,
    val na1: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RequestAndCredentialsDto

        if (!streamingPayload.contentEquals(other.streamingPayload)) return false
        if (!streamingSignature.contentEquals(other.streamingSignature)) return false
        if (na1 != other.na1) return false

        return true
    }

    override fun hashCode(): Int {
        var result = streamingPayload.contentHashCode()
        result = 31 * result + streamingSignature.contentHashCode()
        result = 31 * result + na1
        return result
    }


}
