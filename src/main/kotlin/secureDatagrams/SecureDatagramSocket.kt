package secureDatagrams

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketAddress
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.*
import java.util.function.IntFunction
import java.util.stream.Collectors
import java.util.stream.IntStream
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class SecureDatagramSocket : DatagramSocket {

    private val encryptCipher: Cipher
    private val decryptCipher: Cipher
    private val key: SecretKey
    private val hMac: Mac

    init {
        val kg = KeyGenerator.getInstance(Settings.algorithm)
        kg.init(SecureRandom(Settings.symPassword.toByteArray()))
        key = kg.generateKey()

        encryptCipher = Cipher.getInstance(Settings.symmetricSuite)
        decryptCipher = Cipher.getInstance(Settings.symmetricSuite)

        if (!"".equals(Settings.iv)) {
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(Settings.iv))
            decryptCipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(Settings.iv))
        } else {
            encryptCipher.init(Cipher.ENCRYPT_MODE, key)
            decryptCipher.init(Cipher.DECRYPT_MODE, key)
        }

        hMac = Mac.getInstance(Settings.hmacSuite)
        hMac.init(SecretKeySpec(Settings.hmacKey, Settings.hmacSuite))
    }

    constructor(a: SocketAddress) : super(a)

    constructor() : super()

    /**
     * Unlike its parent implementation, the [DatagramPacket.buf] is replaced by a new one
     * since the old one will contain encrypted data
     * @see DatagramSocket.send
     */
    override fun send(p: DatagramPacket) {
//        println("${String(p.data,0,p.length)} ${p.length}")
        toSimplifiedSRTSPPacket(p)
        super.send(p)
    }

    override fun receive(p: DatagramPacket) {
        super.receive(p)
//        println("${String(p.data,0,p.length)} ${p.length}")
        fromSimplifiedSRTSPPacket(p)
    }

    private val version: Byte = 0b0001
    private val msgType: Byte = 0b0000

    private fun toSimplifiedSRTSPPacket(p: DatagramPacket) {
        val cipherText = ByteArray(1 + 2 + encryptCipher.getOutputSize(p.length) + hMac.macLength)
        val ctLength = encryptCipher.doFinal(p.data, 0, p.length, cipherText, 1 + 2)
        hMac.update(cipherText, 1 + 2, ctLength)
        hMac.doFinal(cipherText, 1 + 2 + ctLength)
        ByteBuffer.wrap(cipherText).put(CryptoTools.makeHeader(version,msgType,ctLength.toShort()))
//        println(BitSet.valueOf(CryptoTools.makeHeader(version,msgType,ctLength)).toBinaryString())
        p.data = cipherText
    }

    private fun fromSimplifiedSRTSPPacket(p: DatagramPacket) {
        val frameSize = ByteBuffer.wrap(p.data).getShort(1)
        val encryptedFrame = p.data.copyOfRange(3, 3 + frameSize)
        val receivedMac = p.data.copyOfRange(3 + frameSize, p.length)
        CryptoTools.checkHmac(hMac,encryptedFrame,receivedMac)
        p.length = decryptCipher.doFinal(encryptedFrame, 0, encryptedFrame.size, p.data)
    }
}
