package secureDatagrams

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import java.util.stream.Collectors
import java.util.stream.IntStream
import javax.crypto.Mac
import kotlin.experimental.and
import kotlin.experimental.or


class CryptoTools {
    companion object {


        fun checkHmac(hMac: Mac, frame: ByteArray, receivedMac: ByteArray) {
            if (!MessageDigest.isEqual(hMac.doFinal(frame), receivedMac)) {
                throw IllegalStateException()
            }
        }

        fun makeHeader(version: Byte, msgType: Byte, len: Short): ByteArray {
            val versionAndType = version.toInt().shl(4).toByte() or (msgType and 0x0F)
            return ByteBuffer.wrap(ByteArray(EncapsulatedPacket.HEADER_SIZE))
                .put(versionAndType)
                .putShort(len)
                .array()
        }

        fun BitSet.toBinaryString(): String? {
            return IntStream.range(0, length())
                .mapToObj { b: Int -> if (get(b)) "1" else "0" }
                .collect(Collectors.joining())
        }

        private val RANDOM: Random = SecureRandom()
        fun salt(length: Int): String {
            val sb = StringBuilder(length)
            for (i in 0 until length) {
                val c: Int = RANDOM.nextInt(62)
                if (c <= 9) {
                    sb.append(c.toString())
                } else if (c < 36) {
                    sb.append(('a'.code + c - 10).toChar())
                } else {
                    sb.append(('A'.code + c - 36).toChar())
                }
            }
            return sb.toString()
        }

        fun rand(b: Int): Int {
            return RANDOM.nextInt(b)
        }

        fun checkHash(shaDig: MessageDigest, dataBytes: ByteArray, shaBytes: ByteArray) {
            if (!shaDig.digest(dataBytes).contentEquals(shaBytes)){
                throw IllegalStateException()
            }
        }

    }
}