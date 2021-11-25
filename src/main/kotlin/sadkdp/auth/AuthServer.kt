package sadkdp.auth

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.protobuf.ProtoBuf
import movies.Movie
import movies.MoviesRepository
import sadkdp.dto.*
import secureDatagrams.CryptoTools
import secureDatagrams.EncapsulatedPacketHash
import secureDatagrams.Settings
import users.UsersRepository
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.security.*
import java.util.*
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
    private var lastMovie: Movie? = null
    private val outSocket = DatagramSocket()
    private val random = SecureRandom()

    private var lastN1: Int? = null
    private var lastN3: Int? = null

    fun processMessage(p: DatagramPacket) {
        val socketAddress = InetSocketAddress(p.address, getProxyPort())
        try {
            val ep = EncapsulatedPacketHash(p)
            if (ep.version != EncapsulatedPacketHash.VERSION) {
                throw RuntimeException("Wrong Packet Version")
            }
            val hello = 1
            val authentication = 3
            val payment = 5
            when (ep.msgType.toInt()) {
                hello -> sendAuthenticationRequest(decodeHello(ep), socketAddress)
                authentication -> sendPaymentRequest(decodeAuthentication(ep), socketAddress)
                payment -> sendTicketCredentials(decodePayment(ep), socketAddress, ep)
                9 -> throw RuntimeException("Client Had An Error")
                else -> throw RuntimeException("Invalid msgType")
            }
        } catch (e: Exception) {
            val error = (e.message ?: "Unknown Error").toByteArray()
            val ep = EncapsulatedPacketHash(error, error.size, 10)
            outSocket.send(DatagramPacket(ep.data, ep.data.size, socketAddress))
            throw e
        }
    }

    private fun publicKey(alias: String): PublicKey {
        return keyStore.getCertificate(alias).publicKey
    }

    private fun privateKey(): PrivateKey {
        return keyStore.getKey("signal", "password".toCharArray()) as PrivateKey
    }

    private fun String.decodeHex(): ByteArray {
        check(length % 2 == 0) { "Must have an even length" }

        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }

    private inline fun <reified T> sendPacket(dto: T, msgType: Byte, socketAddress: SocketAddress) {
        val toSend = ProtoBuf.encodeToByteArray(dto)
        val ep = EncapsulatedPacketHash(toSend, toSend.size, msgType)
        outSocket.send(DatagramPacket(ep.data, ep.data.size, socketAddress))
    }

    private fun decodeHello(ep: EncapsulatedPacketHash): HelloDto {
        return ProtoBuf.decodeFromByteArray(ep.dataBytes)
    }

    private fun sendAuthenticationRequest(hello: HelloDto, socketAddress: SocketAddress) {
        val (userId, proxyBoxId) = hello
        if (!publicKey("proxy").encoded.contentEquals(proxyBoxId.decodeHex())) {
            throw RuntimeException("Wrong ProxyBox")
        }
        if (users.getUser(userId) == null) {
            throw RuntimeException("User does not exist")
        }
        val salt = "salt"//CryptoTools.salt(4) //Todo save this???
        val counter = 123//random.nextInt(10) //TODO pbe difficulty
        val n1 = random.nextInt()
        lastN1 = n1
        sendPacket(AuthenticationRequestDto(n1, salt, counter), 2, socketAddress)
    }

    private fun decodeAuthentication(ep: EncapsulatedPacketHash): AuthenticationDto {
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

        if (n1_ - 1 != lastN1) {
            throw RuntimeException("$n1_ -1 != $lastN1")
        }

        if (movieId !in movies.movies) {
            throw RuntimeException("Movie $movieId not found")
        }

        lastMovie = movies.movies[movieId]!!
        val n3 = CryptoTools.rand(256)
        val payload = PaymentRequestDto.Payload(n2 + 1, n3, lastMovie!!.price)
        lastN3 = n3

        val signature = AuthHelper.sign(payload, privateKey())

        sendPacket(PaymentRequestDto(payload, signature), 4, socketAddress)
    }

    private fun decodePayment(ep: EncapsulatedPacketHash): PaymentDto {
        return ProtoBuf.decodeFromByteArray(ep.dataBytes)
    }

    private fun sendTicketCredentials(payment: PaymentDto, socketAddress: SocketAddress, ep: EncapsulatedPacketHash) {
        val (payload, signature1) = payment
        AuthHelper.verify(payload, signature1, publicKey("proxy"))

        val (n3_, n4, coin) = payload

        if (n3_ - 1 != lastN3) {
            throw RuntimeException("$n3_ -1 != $lastN3")
        }

        val k = Json.decodeFromString<ByteArray>(File("config/signal/bankkey.json").readText())

        if (!k.contentEquals(coin.issuerHeader.issuerPublicKey)) {
            throw RuntimeException("Invalid bank issuer key")
        }
        coin.verifySignature()
        if (coin.value < (lastMovie?.price ?: Int.MAX_VALUE)) {
            throw RuntimeException("Coin worth too little")
        }


        val payloadContent =
            TicketCredentialsDto.Payload(ep.from.hostAddress, getProxyPort(), lastMovie!!.filmName, settings, n4 + 1)

        val proxyPayload = AuthHelper.encrypt(payloadContent, publicKey("proxy"))
        val streamingPayload = AuthHelper.encrypt(payloadContent.copy(nc = random.nextInt()), publicKey("streaming"))

        val proxySignature = AuthHelper.sign(proxyPayload, privateKey())
        val streamingSignature = AuthHelper.sign(streamingPayload, privateKey())

        val dto = TicketCredentialsDto(proxyPayload, proxySignature, streamingPayload, streamingSignature)
        sendPacket(dto, 6, socketAddress)
    }

    private fun getProxyPort(): Int {
        val inputStream: InputStream
        inputStream = FileInputStream("config/signal/signal.properties")
        val properties = Properties()
        properties.load(inputStream)
        return properties.getProperty("proxyport").toInt()
    }
}