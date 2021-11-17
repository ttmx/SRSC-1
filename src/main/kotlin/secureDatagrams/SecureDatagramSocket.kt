package secureDatagrams

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketAddress
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import kotlin.system.exitProcess

class SecureDatagramSocket : DatagramSocket {

    private lateinit var cipher : Cipher
    private lateinit var key :SecretKey

    constructor(a: SocketAddress) : super(a) {
        init()
    }

    constructor() : super(){
        init()
    }

    private fun init(){
        val kg: KeyGenerator = KeyGenerator.getInstance("AES")
        kg.init(SecureRandom("asd".toByteArray()))
        key = kg.generateKey()
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    }

    override fun send(p: DatagramPacket) {
        // encryption
//        println("${String(p.data,0,p.length)} ${p.length}")
        cipher.init(Cipher.ENCRYPT_MODE, key,IvParameterSpec(ByteArray(16)))
        p.data = cipher.doFinal(p.data,0,p.length)
        super.send(p)
    }

    override fun receive(p: DatagramPacket) {
        super.receive(p)
//        println("${String(p.data,0,p.length)} ${p.length}")
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(ByteArray(16)))
        p.data = cipher.doFinal(p.data,0,p.length)
    }
}
