package sadkdp.dto

import kotlinx.serialization.Serializable

@Serializable
data class PaymentRequestDto(val payload: Payload, val signature: ByteArray) {
    @Serializable
    data class Payload(val n2_: Int, val n3: Int, val price: Int)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PaymentRequestDto

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
