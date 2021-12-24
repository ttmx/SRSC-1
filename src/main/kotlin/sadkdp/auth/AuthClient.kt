package sadkdp.auth

import coins.Coin
import coins.CoinsRepository
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import sadkdp.dto.*
import secureDatagrams.CryptoTools
import secureDatagrams.DTLSSocket
import secureDatagrams.EncapsulatedPacketHash
import java.io.FileInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketAddress
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec


@ExperimentalSerializationApi
class AuthClient(
    private val coins: CoinsRepository,
    inSocketAddress: SocketAddress,
    private val outSocketAddress: SocketAddress,
    private val keyStore: KeyStore
) {
    private var lastN2: Int? = null
    private val socket :DTLSSocket
    private val random = SecureRandom()

    init {
        val inputStream = FileInputStream("config/proxy/dtls.properties")
        val p = Properties()
        p.load(inputStream)
        socket = DTLSSocket("config/trustbase.p12","config/proxy/selftls.p12",p,false,inSocketAddress)

    }

    private fun publicKey(alias: String): PublicKey {
        return keyStore.getCertificate(alias).publicKey
    }

    private fun privateKey(): PrivateKey {
        return keyStore.getKey("proxy", "password".toCharArray()) as PrivateKey
    }

    private inline fun <reified T> sendPacket(dto: T, msgType: Byte, socketAddress: SocketAddress) {
        val toSend = ProtoBuf.encodeToByteArray(dto)
        val ep = EncapsulatedPacketHash(toSend, toSend.size, msgType)
        socket.send(DatagramPacket(ep.data, ep.data.size, socketAddress))
    }

    fun getStreamInfo(
        userId: String,
        password: String,
        proxyBoxId: String,
        movieId: String
    ): Triple<TicketCredentialsDto.Payload, ByteArray, ByteArray> {
        try {
            sendHello(userId, proxyBoxId)
            val authenticationRequest = receiveAuthenticationRequest()
            sendAuthentication(authenticationRequest, password, movieId)
            val paymentRequest = receivePaymentRequest()
            sendPayment(paymentRequest)
            val ticketCredentials = receiveTicketCredentials()
            socket.close()
            return ticketCredentials
        } catch (e: Exception) {
            val error = (e.message ?: "Unknown Error").toByteArray()
            val ep = EncapsulatedPacketHash(error, error.size, 9)
            socket.send(DatagramPacket(ep.data, ep.data.size, outSocketAddress))
            throw e
        }
    }

    private fun sendHello(userId: String, proxyBoxId: String) {
        val helloDto = ProtoBuf.encodeToByteArray(HelloDto(userId, proxyBoxId))
        val packet = ByteBuffer.allocate(EncapsulatedPacketHash.HEADER_SIZE + helloDto.size)
            .put(CryptoTools.makeHeader(EncapsulatedPacketHash.VERSION, 1, helloDto.size.toShort()))
            .put(helloDto)
            .array()
        socket.send(DatagramPacket(packet, packet.size, outSocketAddress))
    }

    private fun receiveAuthenticationRequest(): AuthenticationRequestDto {
        val data = receivePacket()
        return ProtoBuf.decodeFromByteArray(data.dataBytes)
    }

    private fun sendAuthentication(
        authenticationRequestDto: AuthenticationRequestDto,
        password: String,
        movieId: String
    ) {
        val (n1, salt, counter) = authenticationRequestDto

        val cEnc = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC")

        val pbeSpec = PBEKeySpec(password.toCharArray(), salt.toByteArray(), counter)
        val secretKey = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES")
            .generateSecret(pbeSpec)

        cEnc.init(Cipher.ENCRYPT_MODE, secretKey)

        lastN2 = random.nextInt()
        val out = cEnc.doFinal(
            ProtoBuf.encodeToByteArray(AuthenticationDto(n1 + 1, lastN2!!, movieId))
        )
        val ep = EncapsulatedPacketHash(out, out.size, 3)
        socket.send(DatagramPacket(ep.data, ep.data.size, outSocketAddress))
    }

    private fun receivePaymentRequest(): PaymentRequestDto.Payload {
        val data = receivePacket()
        val (payload, signature) = ProtoBuf.decodeFromByteArray<PaymentRequestDto>(data.dataBytes)
        AuthHelper.verify(payload, signature, publicKey("signal"))
        return payload
    }

    private fun sendPayment(paymentRequest: PaymentRequestDto.Payload) {
        val (n2_, n3, price) = paymentRequest

        fun getCoin(): Coin {
            // just get the first coin
            return coins.coins.first { it.value >= price }
        }

        if (n2_ - 1 != lastN2) {
            throw RuntimeException()
        }
        val payment = PaymentDto.Payload(n3 + 1, random.nextInt(), getCoin())
        val signature = AuthHelper.sign(payment, privateKey())

        sendPacket(PaymentDto(payment, signature), 5, outSocketAddress)
    }

    private fun receiveTicketCredentials(): Triple<TicketCredentialsDto.Payload, ByteArray, ByteArray> {
        val data = receivePacket()
        val (proxyPayload, proxySignature,
            streamingPayload, streamingSignature) = ProtoBuf.decodeFromByteArray<TicketCredentialsDto>(data.dataBytes)
        AuthHelper.verify(proxyPayload, proxySignature, publicKey("signal"))
        AuthHelper.verify(streamingPayload, streamingSignature, publicKey("signal"))
        val payloadContent = AuthHelper.decrypt<TicketCredentialsDto.Payload>(proxyPayload, privateKey())
        return Triple(payloadContent, streamingPayload, streamingSignature)
    }

    private fun receivePacket(): EncapsulatedPacketHash {
        val buffer = ByteArray(4 * 1024)
        val inPacket = DatagramPacket(buffer, buffer.size)
        socket.receive(inPacket)
        val data = EncapsulatedPacketHash(inPacket)
        if (data.version != EncapsulatedPacketHash.VERSION) {
            throw RuntimeException("Wrong Packet Version")
        }
        return when (data.msgType.toInt()) {
            2, 4, 6 -> data
            10 -> throw RuntimeException("Server Had An Error")
            else -> throw RuntimeException("Invalid msgType")
        }
    }

}