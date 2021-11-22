package secureDatagrams

import java.net.DatagramPacket
import java.net.InetAddress
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and
import kotlin.properties.Delegates

class EncapsulatedPacket {
    companion object {
        private val hMac: Mac = Mac.getInstance(Settings.hmacSuite)
        const val HEADER_SIZE = 1 + 2
        const val VERSION: Byte = 1

        init {
            hMac.init(SecretKeySpec(Settings.hmacKey, Settings.hmacSuite))
        }
    }

    var port by Delegates.notNull<Int>()
    lateinit var from: InetAddress
    val data: ByteArray
    val len: Short
        get() = ByteBuffer.wrap(this.data).getShort(1)

    val msgType: Byte
        get() = this.data[0] and 0x01

    val version: Byte
        get() = (this.data[0].toInt() ushr 4).toByte()

    private val hmacBytes: ByteArray
        get() = this.data.copyOfRange(HEADER_SIZE + len, HEADER_SIZE + len + hMac.macLength)

    val dataBytes: ByteArray
        get() = this.data.copyOfRange(HEADER_SIZE, HEADER_SIZE + len)


    constructor(data: ByteArray, address: InetAddress, port: Int) {
        this.data = data
        this.from = address
        this.port = port
        CryptoTools.checkHmac(hMac, dataBytes, hmacBytes)
    }

    constructor(packet: DatagramPacket) {
        this.data = packet.data
        this.from = packet.address
        this.port = packet.port
        CryptoTools.checkHmac(hMac, dataBytes, hmacBytes)
    }

    constructor(raw: ByteArray, len: Int, msgType: Byte) {
        this.data = ByteArray(HEADER_SIZE + len + hMac.macLength)
        raw.copyInto(this.data, HEADER_SIZE)
        ByteBuffer.wrap(this.data).put(CryptoTools.makeHeader(VERSION, msgType, len.toShort()))
        hMac.update(this.data, HEADER_SIZE, len)
        hMac.doFinal(this.data, HEADER_SIZE + len)
    }


}