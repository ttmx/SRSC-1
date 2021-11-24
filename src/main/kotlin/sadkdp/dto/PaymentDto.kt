package sadkdp.dto

import coins.Coin
import kotlinx.serialization.Serializable

@Serializable
data class PaymentDto(val payload: Payload, val signature: ByteArray) {
    @Serializable
    data class Payload(val n3_: Int, val n4: Int, val coin: Coin)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PaymentDto

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
