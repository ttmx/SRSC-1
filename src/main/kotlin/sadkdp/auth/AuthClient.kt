package sadkdp.auth

import coins.Coin
import coins.CoinsRepository
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import sadkdp.dto.*
import secureDatagrams.CryptoTools
import secureDatagrams.EncapsulatedPacket
import users.UsersRepository
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketAddress
import java.nio.ByteBuffer
import java.security.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


@ExperimentalSerializationApi
class AuthClient(
    private val inSocket: DatagramSocket,
    private val outSocketAddress: SocketAddress,
    private val keyStore: KeyStore
) {

    private val outSocket = DatagramSocket()
    private val users = UsersRepository("users.json")
    private val coins = CoinsRepository()

    private fun publicKey(alias: String): PublicKey {
        return keyStore.getCertificate(alias).publicKey
    }

    private fun privateKey(): PrivateKey {
        return keyStore.getKey("proxy", "password".toCharArray()) as PrivateKey
    }

    private inline fun <reified T> sendPacket(dto: T, msgType: Byte, socketAddress: SocketAddress) {
        val toSend = ProtoBuf.encodeToByteArray(dto)
        //TODO version needs to be parameterized hmac also broken
        val ep = EncapsulatedPacket(toSend, toSend.size, msgType)
        outSocket.send(DatagramPacket(ep.data, ep.data.size, socketAddress))
    }

    fun getStreamInfo(userId: String, password: String, proxyBoxId: String, coinId: String, movieId: String) {
        val authUser = users.authUser(userId, password)
        val coin = coins.getCoin(coinId)
        sendHello(userId, proxyBoxId)
        val authenticationRequest = receiveAuthenticationRequest()
        sendAuthentication(authenticationRequest, authUser.password, movieId)
        val paymentRequest = receivePaymentRequest()
        sendPayment(paymentRequest)
        receiveTicketCredentials()
    }

    private fun sendHello(userId: String, proxyBoxId: String) {
        val helloDto = ProtoBuf.encodeToByteArray(HelloDto(userId, proxyBoxId))
        val packet = ByteBuffer.allocate(EncapsulatedPacket.HEADER_SIZE + helloDto.size)
            .put(CryptoTools.makeHeader(0b010/*TODO*/, 0b001, helloDto.size.toShort()))
            .put(helloDto)
            .array()
        outSocket.send(DatagramPacket(packet, packet.size, outSocketAddress))
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
        val keyBytes = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES")
            .generateSecret(pbeSpec)
            .encoded

        val ivBytes = ByteArray(cEnc.blockSize)
        SecureRandom().nextBytes(ivBytes)

        cEnc.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(keyBytes, "DESede"),
            IvParameterSpec(ivBytes)
        )

        val out = cEnc.doFinal(
            ProtoBuf.encodeToByteArray(AuthenticationDto(n1 + 1, SecureRandom().nextInt(), movieId))
        )
        val ep = EncapsulatedPacket(out, out.size, 3) //TODO version needs to be parameterized hmac also broken
        outSocket.send(DatagramPacket(ep.data, ep.data.size, outSocketAddress))
    }

    private fun receivePaymentRequest(): PaymentRequestDto.Payload {
        val data = receivePacket()
        val (payload, signature1) = ProtoBuf.decodeFromByteArray<PaymentRequestDto>(data.dataBytes)
        AuthHelper.verify(payload, signature1, publicKey("signal"))
        return payload
    }

    private fun sendPayment(paymentRequest: PaymentRequestDto.Payload) {
        fun getCoin(): Coin {
            TODO("check price")
        }
        val (n2_, n3, price) = paymentRequest
        val payment = PaymentDto.Payload(n3 + 1, SecureRandom().nextInt(), getCoin())
        val signature = AuthHelper.sign(payment, privateKey())

        sendPacket(PaymentDto(payment, signature), 5, outSocketAddress)
    }

    private fun receiveTicketCredentials(): Pair<TicketCredentialsDto.Payload.Content, ByteArray> {
        val data = receivePacket()
        val (payload, signature1) = ProtoBuf.decodeFromByteArray<TicketCredentialsDto>(data.dataBytes)
        AuthHelper.verify(payload, signature1, publicKey("signal"))
        val (proxyPayload, streamingPayload) = payload
        val payloadContent = AuthHelper.decrypt<TicketCredentialsDto.Payload.Content>(proxyPayload, privateKey())
        return Pair(payloadContent, streamingPayload)
    }

    private fun receivePacket(): EncapsulatedPacket {
        val buffer = ByteArray(4 * 1024)
        val inPacket = DatagramPacket(buffer, buffer.size)
        inSocket.receive(inPacket)
        val data = EncapsulatedPacket(inPacket) //TODO EncapsulatedPacket assumes hmac (version check missing)
        return when (data.msgType.toInt()) {
            2, 4, 6 -> data
            10 -> throw RuntimeException(/*TODO*/)
            else -> throw RuntimeException(/*TODO*/)
        }
    }

}