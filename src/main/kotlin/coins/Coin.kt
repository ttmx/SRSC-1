package coins

import kotlinx.datetime.LocalDate
import kotlinx.serialization.Serializable


@Serializable
data class Coin(
    val coinId: String,
    val coinIssuer: String,
    val value: Int,
    val expireDate: LocalDate,
    val coinAuthenticity: ByteArray,
    val IssueSignature: ByteArray,
    val IssuePublicKey: ByteArray,
    val IntegrityProof1: ByteArray,
    val IntegrityProof2: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Coin

        if (coinId != other.coinId) return false
        if (coinIssuer != other.coinIssuer) return false
        if (value != other.value) return false
        if (expireDate != other.expireDate) return false
        if (!coinAuthenticity.contentEquals(other.coinAuthenticity)) return false
        if (!IssueSignature.contentEquals(other.IssueSignature)) return false
        if (!IssuePublicKey.contentEquals(other.IssuePublicKey)) return false
        if (!IntegrityProof1.contentEquals(other.IntegrityProof1)) return false
        if (!IntegrityProof2.contentEquals(other.IntegrityProof2)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = coinId.hashCode()
        result = 31 * result + coinIssuer.hashCode()
        result = 31 * result + value
        result = 31 * result + expireDate.hashCode()
        result = 31 * result + coinAuthenticity.contentHashCode()
        result = 31 * result + IssueSignature.contentHashCode()
        result = 31 * result + IssuePublicKey.contentHashCode()
        result = 31 * result + IntegrityProof1.contentHashCode()
        result = 31 * result + IntegrityProof2.contentHashCode()
        return result
    }
}
