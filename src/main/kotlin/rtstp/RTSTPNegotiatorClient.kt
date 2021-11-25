package rtstp

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import rtstp.dto.RequestAndCredentialsDto
import sadkdp.dto.TicketCredentialsDto
import secureDatagrams.EncapsulatedPacket
import secureDatagrams.SecureDatagramSocket
import java.net.DatagramPacket
import java.net.SocketAddress
import java.security.SecureRandom

@ExperimentalSerializationApi
class RTSTPNegotiatorClient(
    private val streamInfo: Triple<TicketCredentialsDto.Payload, ByteArray, ByteArray>,
    private val outSocketAddress: SocketAddress
) {
    private var lastN1: Int? = null

    private val inSocket = SecureDatagramSocket(
        streamInfo.component1().settings,
        streamInfo.component1().port
    )
    private val outSocket = SecureDatagramSocket(streamInfo.component1().settings)
    private val random = SecureRandom()

    private inline fun <reified T> sendPacket(dto: T, msgType: Byte, socketAddress: SocketAddress) {
        val toSend = ProtoBuf.encodeToByteArray(dto)
        //TODO version needs to be parameterized
        outSocket.sendCustom(DatagramPacket(toSend, toSend.size, socketAddress), msgType)
    }

    fun negotiate(): SecureDatagramSocket {
        sendRequestAndCredentials()
        val ackVerificationDto = receiveVerification()
        sendAckVerification(ackVerificationDto)
        //receiveSyncInitialFrame(syncInitialFrameDto)
        return inSocket
    }

    private fun sendAckVerification(ackVerificationDto: Pair<Int, Int>) {
        sendPacket(ackVerificationDto, 3, outSocketAddress)
    }

    private fun receiveVerification(): Pair<Int, Int> {
        val data = receivePacket()
        val (na1_, na2, verification) = ProtoBuf.decodeFromByteArray<Triple<Int, Int, Boolean>>(data.dataBytes)
        if (na1_ - 1 != lastN1) {
            throw RuntimeException("$na1_ - 1 != $lastN1")
        }
        //TODO verification
        return Pair(na2 + 1, random.nextInt())
    }

    private fun sendRequestAndCredentials() {
        lastN1 = random.nextInt()
        val dto = RequestAndCredentialsDto(streamInfo.second, streamInfo.third, lastN1!!)
        sendPacket(dto, 1, outSocketAddress)
    }

    private fun receivePacket(): EncapsulatedPacket {
        val buffer = ByteArray(4 * 1024)
        val inPacket = DatagramPacket(buffer, buffer.size)
        inSocket.receiveCustom(inPacket)
        val data = EncapsulatedPacket(inPacket) //TODO  (version check missing)
        return when (data.msgType.toInt()) {
            1, 3 -> throw RuntimeException(/*TODO*/)
            else -> data
        }
    }

}