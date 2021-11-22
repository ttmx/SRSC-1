package proxy

import coins.CoinsRepository
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import sadkdp.AuthenticationDto
import sadkdp.AuthenticationRequestDto
import sadkdp.HelloDto
import sadkdp.PaymentRequestDto
import secureDatagrams.CryptoTools
import secureDatagrams.EncapsulatedPacket
import users.UsersRepository
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketAddress
import java.nio.ByteBuffer
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


class Authentication(private val inSocket: DatagramSocket, private val outSocketAddress: SocketAddress) {

    private val outSocket = DatagramSocket()
    private val users = UsersRepository()
    private val coins = CoinsRepository()

    fun getStreamInfo(userId: String, password: String, proxyBoxId: String, coinId: String, movieId: String) {
        val authUser = users.authUser(userId, password)
        val coin = coins.getCoin(coinId)
        sendHello(userId, proxyBoxId)
        val authenticationRequest = receiveAuthenticationRequest()
        sendAuthentication(authenticationRequest, authUser.password, movieId)
        val paymentRequest = receivePaymentRequest()

    }

    private fun sendHello(userId: String, proxyBoxId: String) {
        val helloDto = Json.encodeToString(HelloDto(userId, proxyBoxId)).toByteArray()
        val packet = ByteBuffer.allocate(EncapsulatedPacket.HEADER_SIZE + helloDto.size)
            .put(CryptoTools.makeHeader(0b010/*TODO*/, 0b001, helloDto.size.toShort()))
            .put(helloDto)
            .array()
        outSocket.send(DatagramPacket(packet, packet.size, outSocketAddress))
    }

    private fun receiveAuthenticationRequest(): AuthenticationRequestDto {
        val data = receivePacket()
        return Json.decodeFromString(data.dataBytes.toString())
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
            Json.encodeToString(AuthenticationDto(n1 + 1, SecureRandom().nextInt(), movieId)).toByteArray()
        )
        val ep = EncapsulatedPacket(out, out.size, 3) //TODO version needs to be parameterized hmac also broken
        outSocket.send(DatagramPacket(ep.data, ep.data.size, outSocketAddress))
    }

    private fun receivePaymentRequest(): PaymentRequestDto.Payload {
        fun publicKey(): PublicKey {
            TODO()
        }
        val data = receivePacket()
        val (payload, signature1) = Json.decodeFromString<PaymentRequestDto>(data.dataBytes.toString())
        val signature = Signature.getInstance("SHA512withECDSA", "BC")
        signature.initVerify(publicKey())
        signature.update(signature1)
        if (!signature.verify(Json.encodeToString(payload).toByteArray())) {
            throw RuntimeException(/*TODO*/)
        }
        return payload
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