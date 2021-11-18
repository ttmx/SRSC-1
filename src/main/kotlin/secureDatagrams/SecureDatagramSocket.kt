package secureDatagrams

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketAddress
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class SecureDatagramSocket : DatagramSocket {

    private val encryptCipher: Cipher
    private val decryptCipher: Cipher
    private val key: SecretKey

    init {
        val kg = KeyGenerator.getInstance("AES")
        kg.init(SecureRandom(Settings.symPassword.toByteArray()))
        key = kg.generateKey()
        encryptCipher = Cipher.getInstance(Settings.symmetricSuite)
        encryptCipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(Settings.iv))
        decryptCipher = Cipher.getInstance(Settings.symmetricSuite)
        decryptCipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(Settings.iv))
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
        p.data = encryptCipher.doFinal(p.data, 0, p.length)
        super.send(p)
    }

    /**
     * Unlike its parent implementation, the [DatagramPacket.buf] is replaced by a new one
     * since the old one will contain encrypted data
     * @see DatagramSocket.receive
     */
    override fun receive(p: DatagramPacket) {
        super.receive(p)
//        println("${String(p.data,0,p.length)} ${p.length}")
        p.data = decryptCipher.doFinal(p.data, 0, p.length)
    }
}
