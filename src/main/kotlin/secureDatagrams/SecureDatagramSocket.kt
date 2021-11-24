package secureDatagrams

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketAddress
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class SecureDatagramSocket : DatagramSocket {

    private lateinit var encryptCipher: Cipher
    private lateinit var decryptCipher: Cipher
    private lateinit var key: SecretKey
    private lateinit var hMac: Mac
    private lateinit var sett: Settings

    constructor(serverType: String, a: SocketAddress) : super(a) {
        init(serverType)
    }

    constructor(serverType: String) : super() {
        init(serverType)
    }

    fun init(serverType: String) {
        //TODO change this up
        sett = Settings.getSettingsFromFile(serverType)
        val kg = KeyGenerator.getInstance(sett.algorithm)
        kg.init(SecureRandom(sett.symPassword.toByteArray()))
        key = kg.generateKey()
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
        val cipherText = ByteArray(encryptCipher.getOutputSize(p.length))
        val ctLength = encryptCipher.doFinal(p.data, 0, p.length, cipherText)
        val ep = EncapsulatedPacket(cipherText, ctLength, msgType)
//        println(BitSet.valueOf(CryptoTools.makeHeader(version,msgType,ctLength)).toBinaryString())
        p.data = ep.data
    }

    private fun fromSimplifiedSRTSPPacket(p: DatagramPacket) {
        val ep = EncapsulatedPacket(p)
        p.length = decryptCipher.doFinal(ep.dataBytes, 0, ep.len.toInt(), p.data)
    }
}
