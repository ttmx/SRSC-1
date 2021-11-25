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
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom

@ExperimentalSerializationApi
class RTSTPNegotiatorServer(port: Int, private val keyStore: KeyStore) {
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
        //TODO version needs to be parameterized
        outSocket.sendCustom(DatagramPacket(toSend, toSend.size, socketAddress), msgType)
    }

    fun awaitNegotiation(): SecureDatagramSocket {
        val (content, verificationDto) = receiveRequestAndCredentials()
        val (ip, port, movieId, settings, nc) = content
        inSocket.useSettings(settings)
        outSocket.useSettings(settings)
        outSocketAddress = InetSocketAddress(ip, 9999)
        sendVerification(verificationDto, content)
        val syncInitialFrameDto = receiveAckVerification()
        //sendSyncInitialFrame(syncInitialFrameDto)
        return outSocket
    }

    private fun sendSyncInitialFrame(ackVerificationDto: Pair<Int, Int>) {
        val (na2_, na3) = ackVerificationDto
        
    }

    private fun receiveAckVerification() : Pair<Int, Int>{
        val data = receivePacket()
        val (na2_, na3) = ProtoBuf.decodeFromByteArray<Pair<Int, Int>>(data.dataBytes)
        return Pair(na3 + 1, /*TODO frame*/123)
    }

    private fun sendVerification(
        verificationDto: Triple<Int, Int, Boolean>,
        config: TicketCredentialsDto.Payload
    ) {
        sendPacket(verificationDto, 2, outSocketAddress)
    }

    private fun receiveRequestAndCredentials(): Pair<TicketCredentialsDto.Payload, Triple<Int, Int, Boolean>> {
        val data = receivePacket()
        val (payload, signature) = ProtoBuf.decodeFromByteArray<RequestAndCredentialsDto>(data.dataBytes)
        AuthHelper.verify(payload, signature, publicKey("signal"))
        val content = AuthHelper.decrypt<TicketCredentialsDto.Payload>(payload, privateKey())
        val (ip, port, movieId, settings, nc) = content
        return Pair(content, Triple(nc + 1, random.nextInt(), true))
    }

    private fun receivePacket(): EncapsulatedPacket {
        val buffer = ByteArray(4 * 1024)
        val inPacket = DatagramPacket(buffer, buffer.size)
        inSocket.receiveCustom(inPacket)
        val data = EncapsulatedPacket(inPacket) //TODO  (version check missing)
        return when (data.msgType.toInt()) {
            1 -> data
            2, 4 -> throw RuntimeException(/*TODO*/)
            else -> data
        }
    }
}