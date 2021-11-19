package secureDatagrams

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

class EncapsulatedPacket {
    companion object {
        private val hMac: Mac = Mac.getInstance(Settings.hmacSuite)
        private const val headerSize = 1 + 2
        private const val version: Byte = 1

        init {
            hMac.init(SecretKeySpec(Settings.hmacKey, Settings.hmacSuite))
        }
    }

    val data: ByteArray
    val len: Short
        get() {
            return ByteBuffer.wrap(this.data).getShort(1)
        }
    val msgType: Byte
        get() {
            return this.data[0] and 15
        }
    val version: Byte
        get() {
            return (this.data[0].toInt() shr 4).toByte()
        }
    private val hmacBytes: ByteArray
        get() {
            return this.data.copyOfRange(headerSize + len, headerSize + len + hMac.macLength)
        }

    val dataBytes: ByteArray
        get() {
            return this.data.copyOfRange(headerSize, headerSize + len)
        }
    constructor(data: ByteArray, len: Int) {
        this.data = data
        CryptoTools.checkHmac(hMac,dataBytes,hmacBytes)
    }


    constructor(data: ByteArray, len: Int, msgType: Byte) {
        this.data = ByteArray(headerSize + len + hMac.macLength)
        data.copyInto(this.data, headerSize)
        ByteBuffer.wrap(this.data).put(CryptoTools.makeHeader(1, msgType, len.toShort()))
        hMac.update(this.data, headerSize, len)
        hMac.doFinal(this.data, headerSize + len)
    }


}