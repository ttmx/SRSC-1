package secureDatagrams

import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.util.*

internal class SignalHelper(
    private val userid: String,
    private val proxyboxid: String,
    private val port: Int,
    private val s: DatagramSocket
) {
    fun processMessage(p: DatagramPacket) {
        val ep = EncapsulatedPacket(p)
        when (ep.msgType.toInt()) {
            1 -> respondHello(ep)
            3 -> respondAuthentication(ep)
            5 -> respondPayment(ep)
        }

    }

    private fun respondHello(p: EncapsulatedPacket) {
        val d = ProtoBuf.decodeFromByteArray<sadkdp.HelloDto>(p.dataBytes)
        //Todo currently single user and single proxyboxid
        if (d.proxyBoxId != proxyboxid || d.userId != userid) {
            return
        }
        val salt = CryptoTools.salt(4)//Todo save this???
        val counter = CryptoTools.rand(256)
        val nonce = CryptoTools.rand(256)
        val toSend = ProtoBuf.encodeToByteArray(sadkdp.AuthenticationRequestDto(nonce, salt, counter))
        s.send(DatagramPacket(toSend, toSend.size, p.from, p.port))
    }

    private fun respondAuthentication(p: EncapsulatedPacket) {
        val d = ProtoBuf.decodeFromByteArray<SADKDPPacket.Authentication>(p.dataBytes)
        //TODO ACTUALLY DECODE THIS AND NOT USE STATIC VALUEs
        var nonce = CryptoTools.rand(256)
        val a = SADKDPPacket.Authentication.Challenge(4, nonce, "")
        //Todo currently single user and single proxyboxid
        if (/* TODO nonce != previous nonce +1*/false) {
            return
        }
        //Todo dynamic price

        nonce = CryptoTools.rand(256)
        val f = SADKDPPacket.PaymentRequest.ChallResponse(10f, 5, nonce)
        val k = SADKDPPacket.PaymentRequest(
            ProtoBuf.encodeToByteArray(f),
            ProtoBuf.encodeToByteArray("I dont know lol") // Todo
        )

        val toSend = ProtoBuf.encodeToByteArray(k)
        s.send(DatagramPacket(toSend, toSend.size, p.from, p.port))
    }

    private fun respondPayment(s: EncapsulatedPacket) {
        //TODO("Not yet implemented")
    }
}