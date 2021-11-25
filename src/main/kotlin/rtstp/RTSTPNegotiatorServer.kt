package rtstp

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import rtstp.dto.RequestAndCredentialsDto
import sadkdp.auth.AuthHelper
import sadkdp.dto.TicketCredentialsDto
import secureDatagrams.EncapsulatedPacket
import secureDatagrams.SecureDatagramSocket
import java.net.DatagramPacket
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom

@ExperimentalSerializationApi
class RTSTPNegotiatorServer(port: Int, private val keyStore: KeyStore) {
    private var lastNa2: Int? = null
    private val inSocket = SecureDatagramSocket(port)
    private val outSocket = SecureDatagramSocket()
    private val random = SecureRandom()
    private lateinit var outSocketAddress: SocketAddress;


    private fun publicKey(alias: String): PublicKey {
        return keyStore.getCertificate(alias).publicKey
    }

    private fun privateKey(): PrivateKey {
        return keyStore.getKey("streaming", "password".toCharArray()) as PrivateKey
    }

    private inline fun <reified T> sendPacket(dto: T, msgType: Byte, socketAddress: SocketAddress) {
        val toSend = ProtoBuf.encodeToByteArray(dto)
        outSocket.sendCustom(DatagramPacket(toSend, toSend.size, socketAddress), msgType)
    }

    fun awaitNegotiation(): Triple<InetSocketAddress, String, SecureDatagramSocket> {
        val (content, verificationDto) = receiveRequestAndCredentials()
        val (ip, port, movieId, settings, nc) = content
        inSocket.useSettings(settings)
        outSocket.useSettings(settings)
        outSocketAddress = InetSocketAddress(ip, 9999)
        sendVerification(verificationDto, content)
        val syncInitialFrameDto = receiveAckVerification()
        //sendSyncInitialFrame(syncInitialFrameDto)
        return Triple(InetSocketAddress(ip, port), movieId, outSocket)
    }

    private fun sendSyncInitialFrame(ackVerificationDto: Pair<Int, Int>) {
        val (na2_, na3) = ackVerificationDto

    }

    private fun receiveAckVerification(): Pair<Int, Int> {
        val data = receivePacket()
        val (na2_, na3) = ProtoBuf.decodeFromByteArray<Pair<Int, Int>>(data.dataBytes)
        if (na2_ - 1 != lastNa2) {
            throw RuntimeException()
        }
        // No point in sending frame numbers, a random number is good to make equal frames seem different to an attacker
        return Pair(na3 + 1, random.nextInt())
    }

    private fun sendVerification(
        verificationDto: Triple<Int, Int, Boolean>,
        config: TicketCredentialsDto.Payload
    ) {
        sendPacket(verificationDto, 2, outSocketAddress)
    }

    private fun receiveRequestAndCredentials(): Pair<TicketCredentialsDto.Payload, Triple<Int, Int, Boolean>> {
        val data = receivePacket()
        val (payload, signature, na1) = ProtoBuf.decodeFromByteArray<RequestAndCredentialsDto>(data.dataBytes)
        AuthHelper.verify(payload, signature, publicKey("signal"))
        val content = AuthHelper.decrypt<TicketCredentialsDto.Payload>(payload, privateKey())
        lastNa2 = random.nextInt()
        return Pair(content, Triple(na1 + 1, lastNa2!!, true))
    }

    private fun receivePacket(): EncapsulatedPacket {
        val buffer = ByteArray(4 * 1024)
        val inPacket = DatagramPacket(buffer, buffer.size)
        inSocket.receiveCustom(inPacket)
        val data = EncapsulatedPacket(inPacket)
        if (data.version != EncapsulatedPacket.VERSION) {
            throw RuntimeException("Wrong Packet Version")
        }
        return when (data.msgType.toInt()) {
            1 -> data
            2, 4 -> throw RuntimeException("Invalid msgType")
            else -> data
        }
    }
}