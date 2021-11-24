package signal

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import movies.MoviesRepository
import sadkdp.*
import secureDatagrams.CryptoTools
import secureDatagrams.EncapsulatedPacket
import secureDatagrams.Settings
import users.UsersRepository
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.security.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

@ExperimentalSerializationApi
class AuthServer(
    private val users: UsersRepository,
    private val movies: MoviesRepository,
    private val settings: Settings,
    private val keyStore: KeyStore
) {
    private val outSocket = DatagramSocket()
    private val random = SecureRandom()

    companion object {
        private inline fun <reified T> sign(privateKey: PrivateKey, dto: T): ByteArray {
            val privateSignature = Signature.getInstance("SHA512withECDSA", "BC")
            privateSignature.initSign(privateKey)
            privateSignature.update(ProtoBuf.encodeToByteArray(dto))
            return privateSignature.sign()
        }

        private fun verify(signature1: ByteArray, payload: PaymentDto.Payload, publicKey: PublicKey) {
            val signature = Signature.getInstance("SHA512withECDSA", "BC")
            signature.initVerify(publicKey)
            signature.update(signature1)
            if (!signature.verify(ProtoBuf.encodeToByteArray(payload))) {
                throw RuntimeException(/*TODO*/)
            }
        }

        private inline fun <reified T> encrypt(publicKey: PublicKey, dto: T): ByteArray {
            val cipher = Cipher.getInstance("ECIES", "BC")
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            return cipher.doFinal(ProtoBuf.encodeToByteArray(dto))
        }
    }

    fun processMessage(p: DatagramPacket) {
        val ep = EncapsulatedPacket(p)
        val hello = 1
        val authentication = 3
        val payment = 5
        val socketAddress = InetSocketAddress(p.address, p.port)
        when (ep.msgType.toInt()) {
            hello -> sendAuthenticationRequest(decodeHello(ep), socketAddress)
            authentication -> sendPaymentRequest(decodeAuthentication(ep), socketAddress)
            payment -> sendTicketCredentials(decodePayment(ep), socketAddress)
            9 -> throw RuntimeException(/*TODO*/)
            else -> throw RuntimeException(/*TODO*/)
        }
    }

    private fun publicKey(alias: String): PublicKey {
        return keyStore.getCertificate(alias).publicKey
    }

    private fun privateKey(): PrivateKey {
        return keyStore.getKey("signal", "password".toCharArray()) as PrivateKey
    }

    private inline fun <reified T> sendPacket(dto: T, msgType: Byte, socketAddress: SocketAddress) {
        val toSend = ProtoBuf.encodeToByteArray(dto)
        //TODO version needs to be parameterized hmac also broken
        val ep = EncapsulatedPacket(toSend, toSend.size, msgType)
        outSocket.send(DatagramPacket(ep.data, ep.data.size, socketAddress))
    }

    private fun decodeHello(ep: EncapsulatedPacket): HelloDto {
        return ProtoBuf.decodeFromByteArray(ep.dataBytes)
    }

    private fun sendAuthenticationRequest(hello: HelloDto, socketAddress: SocketAddress) {
        val (userId, proxyBoxId) = hello
        //Todo proxyboxid
        if (users.getUser(userId) == null) {
            throw RuntimeException() //TODO send error
        }
        val salt = CryptoTools.salt(4) //Todo save this???
        val counter = random.nextInt(10) //TODO pbe difficulty
        val n1 = random.nextInt()
        sendPacket(AuthenticationRequestDto(n1, salt, counter), 2, socketAddress)
    }

    private fun decodeAuthentication(ep: EncapsulatedPacket): AuthenticationDto {
        val cDec = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC")
        val pbeSpec = PBEKeySpec("password".toCharArray(), "salt".toByteArray(), 123) //TODO
        val keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES")
        val sKey: Key = keyFact.generateSecret(pbeSpec)
        cDec.init(Cipher.DECRYPT_MODE, sKey)
        val plainText = cDec.doFinal(ep.dataBytes)

        return ProtoBuf.decodeFromByteArray(plainText)
    }

    private fun sendPaymentRequest(authentication: AuthenticationDto, socketAddress: SocketAddress) {
        val (n1_, n2, movieId) = authentication

        //Todo currently single user and single proxyboxid
        if (/* TODO nonce != previous nonce +1*/false) {
            return
        }
        //Todo dynamic price

        val n3 = CryptoTools.rand(256)
        val payload = PaymentRequestDto.Payload(n2 + 1, n3, 1)

        val signature = sign(privateKey(), payload)

        sendPacket(PaymentRequestDto(payload, signature), 4, socketAddress)
    }

    private fun decodePayment(ep: EncapsulatedPacket): PaymentDto {
        return ProtoBuf.decodeFromByteArray(ep.dataBytes)
    }

    private fun sendTicketCredentials(payment: PaymentDto, socketAddress: SocketAddress) {
        val (payload, signature1) = payment
        verify(signature1, payload, publicKey("proxy"))

        val (n3_, n4, coin) = payload

        val payloadContent = TicketCredentialsDto.Payload.Content("ip", 12, "movie", settings, n4 + 1)

        val proxyPayload = encrypt(publicKey("proxy"), payloadContent)
        val streamingPayload = encrypt(publicKey("streaming"), payloadContent.copy(nc = random.nextInt()))
        val payload1 = TicketCredentialsDto.Payload(proxyPayload, streamingPayload)

        val signature = sign(privateKey(), payload1)

        sendPacket(TicketCredentialsDto(payload1, signature), 6, socketAddress)
    }
}