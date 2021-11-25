package secureDatagrams

import java.net.DatagramPacket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.security.MessageDigest
import kotlin.experimental.and
import kotlin.properties.Delegates

class EncapsulatedPacketHash {
    companion object {
        internal val shaDig: MessageDigest = MessageDigest.getInstance("SHA-256")
        const val HEADER_SIZE = 1 + 2
        const val VERSION: Byte = 1
    }

    var port by Delegates.notNull<Int>()
    lateinit var from: InetAddress
    val data: ByteArray
    val len: Short
        get() = ByteBuffer.wrap(this.data).getShort(1)

    val msgType: Byte
        get() = this.data[0] and 0x0F

    val version: Byte
        get() = (this.data[0].toInt() ushr 4).toByte()

    val shaBytes: ByteArray
        get() = this.data.copyOfRange(HEADER_SIZE + len, HEADER_SIZE + len + shaDig.digestLength)

    val dataBytes: ByteArray
        get() = this.data.copyOfRange(HEADER_SIZE, HEADER_SIZE + len)


    constructor(data: ByteArray, address: InetAddress, port: Int) {
        this.data = data
        this.from = address
        this.port = port

        if (msgType !in arrayOf(1.toByte(), 2.toByte()))
            CryptoTools.checkHash(shaDig, dataBytes, shaBytes)
    }

    constructor(packet: DatagramPacket) {
        this.data = packet.data
        this.from = packet.address
        this.port = packet.port
        if (msgType !in arrayOf(1.toByte(), 2.toByte()))
            CryptoTools.checkHash(shaDig, dataBytes, shaBytes)
    }

    constructor(raw: ByteArray, len: Int, msgType: Byte) {
        this.data = ByteArray(HEADER_SIZE + len + shaDig.digestLength)
        raw.copyInto(this.data, HEADER_SIZE,0,len)
        ByteBuffer.wrap(this.data).put(CryptoTools.makeHeader(VERSION, msgType, len.toShort()))
        shaDig.update(this.data, HEADER_SIZE, len)
        shaDig.digest(this.data, HEADER_SIZE + len, shaDig.digestLength)
    }


}