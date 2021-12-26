package secureDatagrams

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.nio.ByteBuffer
import java.util.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class SecureRTSTPSocket(
    settings: Settings?,
    ksTrustPath: String,
    ksKeysPath: String,
    dtlsConfig: Properties,
    is_server: Boolean,
    address: SocketAddress
) : DTLSSocket(ksTrustPath, ksKeysPath, dtlsConfig, is_server, address) {

    private lateinit var encryptCipher: Cipher
    private lateinit var decryptCipher: Cipher
    private lateinit var key: SecretKey
    private lateinit var hMac: Mac
    private lateinit var sett: Settings


    init {
        if (settings != null) {
            useSettings(settings)
        }
    }

//    constructor(
//
//        ksTrustPath: String,
//        ksKeysPath: String,
//        dtlsConfig: Properties,
//        is_server: Boolean,
//        address: SocketAddress
//    ) : super(ksTrustPath, ksKeysPath, dtlsConfig, is_server, address)
//
//    constructor(
//        port: Int,
//        ksTrustPath: String,
//        ksKeysPath: String,
//        dtlsConfig: Properties,
//        is_server: Boolean,
//        address: SocketAddress
//    ) : super(ksTrustPath, ksKeysPath, dtlsConfig, is_server, address)
//
//    constructor(
//        settings: Settings, port: Int,
//        ksTrustPath: String,
//        ksKeysPath: String,
//        dtlsConfig: Properties,
//        is_server: Boolean,
//        address: SocketAddress
//        ) : super(ksTrustPath, ksKeysPath, dtlsConfig, is_server, address) {
//        useSettings(settings)
//    }

    fun useSettings(settings: Settings) {
        sett = settings

        key = SecretKeySpec(sett.key, sett.algorithm)
        encryptCipher = Cipher.getInstance(sett.symmetricSuite)
        decryptCipher = Cipher.getInstance(sett.symmetricSuite)

        if (sett.iv != null) {
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(sett.iv))
            decryptCipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(sett.iv))
        } else {
            encryptCipher.init(Cipher.ENCRYPT_MODE, key)
            decryptCipher.init(Cipher.DECRYPT_MODE, key)
        }

        hMac = Mac.getInstance(sett.hmacSuite)
        hMac.init(SecretKeySpec(sett.hmacKey, sett.hmacSuite))

    }

    /**
     * Unlike its parent implementation, the [DatagramPacket.buf] is replaced by a new one
     * since the old one will contain encrypted data
     * @see DatagramSocket.send
     */
    override fun send(p: DatagramPacket) {
        toSimplifiedSRTSPPacket(p, msgType)
        super.send(p)
    }

    fun sendCustom(p: DatagramPacket, msgType: Byte) {
        toSimplifiedSRTSPPacket(p, msgType)
        super.send(p)
    }

    override fun receive(p: DatagramPacket) {
        super.receive(p)
        fromSimplifiedSRTSPPacket(p)
    }

    fun receiveCustom(p: DatagramPacket) {
        super.receive(p)
        val ep = EncapsulatedPacket(p)
        ep.checkHmac()
        if (ep.msgType != 1.toByte()) {
            val decrypted = decryptCipher.doFinal(ep.dataBytes, 0, ep.len.toInt())
            val header = CryptoTools.makeHeader(ep.version, ep.msgType, decrypted.size.toShort())
            p.data = ByteBuffer.wrap(ByteArray(header.size + decrypted.size + ep.hmacBytes.size))
                .put(header)
                .put(decrypted)
                .put(ep.hmacBytes)
                .array()
        }
    }

    private val version: Byte = 0b0001
    private val msgType: Byte = 0b0000

    private fun toSimplifiedSRTSPPacket(p: DatagramPacket, msgType: Byte) {
        if (msgType != 1.toByte()) {
            val cipherText = ByteArray(encryptCipher.getOutputSize(p.length))
            val ctLength = encryptCipher.doFinal(p.data, 0, p.length, cipherText)
            val ep = EncapsulatedPacket(cipherText, ctLength, msgType)
            p.data = ep.data
        } else {
            val ep = EncapsulatedPacket(p.data, p.length, msgType)
            p.data = ep.data
        }
    }

    private fun fromSimplifiedSRTSPPacket(p: DatagramPacket) {
        val ep = EncapsulatedPacket(p)
        if (ep.msgType != 1.toByte()) {
            p.length = decryptCipher.doFinal(ep.dataBytes, 0, ep.len.toInt(), p.data)
        }
    }

}
