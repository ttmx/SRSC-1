package proxy

import coins.Coin
import coins.CoinsRepository
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import sadkdp.*
import secureDatagrams.CryptoTools
import secureDatagrams.EncapsulatedPacket
import users.UsersRepository
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketAddress
import java.nio.ByteBuffer
import java.security.PrivateKey
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
    private val users = UsersRepository("users.json")
    private val coins = CoinsRepository()

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
        fun publicKey(): PublicKey {
            TODO()
        }

        val data = receivePacket()
        val (payload, signature1) = ProtoBuf.decodeFromByteArray<PaymentRequestDto>(data.dataBytes)
        val signature = Signature.getInstance("SHA512withECDSA", "BC")
        signature.initVerify(publicKey())
        signature.update(signature1)
        if (!signature.verify(ProtoBuf.encodeToByteArray(payload))) {
            throw RuntimeException(/*TODO*/)
        }
        return payload
    }

    private fun sendPayment(paymentRequest: PaymentRequestDto.Payload) {
        fun privateKey(): PrivateKey {
            TODO()
        }

        fun getCoin(): Coin {
            TODO("check price")
        }
        val (n2_, n3, price) = paymentRequest
        val payment = PaymentDto.Payload(n3 + 1, SecureRandom().nextInt(), getCoin())
        val encoded = ProtoBuf.encodeToByteArray(payment)
        val privateSignature = Signature.getInstance("SHA512withECDSA", "BC")
        privateSignature.initSign(privateKey())
        privateSignature.update(encoded)
        val signature = privateSignature.sign()

        val out = ProtoBuf.encodeToByteArray(PaymentDto(payment, signature))
        val ep = EncapsulatedPacket(out, out.size, 5) //TODO version needs to be parameterized hmac also broken
        outSocket.send(DatagramPacket(ep.data, ep.data.size, outSocketAddress))
    }

    private fun receiveTicketCredentials(): Pair<TicketCredentialsDto.Payload.Content, ByteArray> {
        fun publicKey(): PublicKey {
            TODO()
        }

        fun privateKey(): PrivateKey {
            TODO()
        }

        val data = receivePacket()
        val (payload, signature1) = ProtoBuf.decodeFromByteArray<TicketCredentialsDto>(data.dataBytes)
        val signature = Signature.getInstance("SHA512withECDSA", "BC")
        signature.initVerify(publicKey())
        signature.update(signature1)
        if (!signature.verify(ProtoBuf.encodeToByteArray(payload))) {
            throw RuntimeException(/*TODO*/)
        }
        val (proxyPayload, streamingPayload) = payload
        val cipher = Cipher.getInstance("ECIES", "BC")
        cipher.init(Cipher.DECRYPT_MODE, privateKey())
        val payloadContent =
            ProtoBuf.decodeFromByteArray<TicketCredentialsDto.Payload.Content>(cipher.doFinal(proxyPayload))
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