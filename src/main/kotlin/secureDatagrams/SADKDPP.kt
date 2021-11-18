package secureDatagrams

import java.io.OutputStream
import kotlin.experimental.and
import kotlin.experimental.or


class SADKDPP {

    @ExperimentalUnsignedTypes
    companion object {
        private const val version: Byte = 1
        fun sendPacket(os: OutputStream, p: String, msgType: Int) {
            os.write(makeHeader(p.length, msgType))
        }


        fun sendPacketHmac(os: OutputStream, p: String, msgType: Int) {
            os.write(makeHeader(p.length, msgType))
            TODO("Have to implement hmac signing")
        }

        private fun makeHeader(len: Int, msgType: Int): ByteArray {
            val arr = ByteArray(3)
            arr[0] = (version and 15).toInt().shl(4).toByte() or
                    version.toInt().shr(4).toByte()
            arr[1] = (len and 0xff).toByte()
            arr[2] = (len shr 8 and 0xff).toByte()
            return arr
        }
    }
}