package rtstp

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import rtstp.dto.RequestAndCredentialsDto
import sadkdp.dto.TicketCredentialsDto
import secureDatagrams.EncapsulatedPacket
import secureDatagrams.SecureRTSTPSocket
import java.io.FileInputStream
import java.net.DatagramPacket
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.security.SecureRandom
import java.util.*

@ExperimentalSerializationApi
class RTSTPNegotiatorClient(
    private val streamInfo: Triple<TicketCredentialsDto.Payload, ByteArray, ByteArray>,
    private val outSocketAddress: SocketAddress
) {
    private var lastN1: Int? = null

    private val socket: SecureRTSTPSocket

    init {
        val inputStream = FileInputStream("config/signal/dtls.properties")
        val p = Properties()
        p.load(inputStream)
        socket = SecureRTSTPSocket(
            streamInfo.component1().settings,
            "config/trustbase.p12",
            "config/proxy/selftls.p12",
            p,
            false,
            InetSocketAddress(streamInfo.component1().port)
        )
        socket.doHandshake(outSocketAddress)
    }

    private val random = SecureRandom()

    private inline fun <reified T> sendPacket(dto: T, msgType: Byte, socketAddress: SocketAddress) {
        val toSend = ProtoBuf.encodeToByteArray(dto)
        this.socket.sendCustom(DatagramPacket(toSend, toSend.size, socketAddress), msgType)
    }

    fun negotiate(): SecureRTSTPSocket {
        sendRequestAndCredentials()
        val ackVerificationDto = receiveVerification()
        sendAckVerification(ackVerificationDto)
        //receiveSyncInitialFrame(syncInitialFrameDto)
        return this.socket
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
        if (!verification) {
            throw RuntimeException("Streaming Server Denied Service")
        }
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
        this.socket.receiveCustom(inPacket)
        val data = EncapsulatedPacket(inPacket)
        if (data.version != EncapsulatedPacket.VERSION) {
            throw RuntimeException("Wrong Packet Version")
        }
        return when (data.msgType.toInt()) {
            1, 3 -> throw RuntimeException("Invalid msgType (expected client type)")
            else -> data
        }
    }

}