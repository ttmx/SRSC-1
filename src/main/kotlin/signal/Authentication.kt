package signal

import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import sadkdp.*
import secureDatagrams.CryptoTools
import secureDatagrams.EncapsulatedPacket
import secureDatagrams.Settings
import users.UsersRepository
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.security.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class Authentication() {
    private val outSocket = DatagramSocket()
    private val users = UsersRepository("users.json")

    private fun sendAuthenticationRequest(p: EncapsulatedPacket) {
        val (userId, proxyBoxId) = ProtoBuf.decodeFromByteArray<HelloDto>(p.dataBytes)
        //Todo proxyboxid
        if (users.getUser(userId) == null) {
            throw RuntimeException() //TODO send error
        }
        val salt = CryptoTools.salt(4) //Todo save this???
        val counter = CryptoTools.rand(256)
        val n1 = CryptoTools.rand(256)
        val toSend = ProtoBuf.encodeToByteArray(sadkdp.AuthenticationRequestDto(n1, salt, counter))
        val ep = EncapsulatedPacket(toSend, toSend.size, 2) //TODO version needs to be parameterized hmac also broken
        outSocket.send(DatagramPacket(ep.data, ep.data.size, p.from, p.port))
    }

    private fun sendPaymentRequest(p: EncapsulatedPacket) {
        val cDec = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC")
        val pbeSpec = PBEKeySpec("password".toCharArray(), "salt".toByteArray(), 123) //TODO
        val keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES")
        val sKey: Key = keyFact.generateSecret(pbeSpec)
        cDec.init(Cipher.DECRYPT_MODE, sKey)

        val plainText = cDec.doFinal(p.dataBytes)

        fun privateKey(): PrivateKey {
            TODO()
        }

        val (n1_, n2, movieId) = ProtoBuf.decodeFromByteArray<AuthenticationDto>(plainText)

        //Todo currently single user and single proxyboxid
        if (/* TODO nonce != previous nonce +1*/false) {
            return
        }
        //Todo dynamic price

        val n3 = CryptoTools.rand(256)
        val payload = PaymentRequestDto.Payload(n2 + 1, n3, 1)
        val encoded = ProtoBuf.encodeToByteArray(payload)
        val privateSignature = Signature.getInstance("SHA512withECDSA", "BC")
        privateSignature.initSign(privateKey())
        privateSignature.update(encoded)
        val signature = privateSignature.sign()

        val paymentRequest = PaymentRequestDto(payload, signature)

        val toSend = ProtoBuf.encodeToByteArray(paymentRequest)
        val ep = EncapsulatedPacket(toSend, toSend.size, 4) //TODO version needs to be parameterized hmac also broken
        outSocket.send(DatagramPacket(ep.data, ep.data.size, p.from, p.port))
    }

    private fun sendTicketCredentials(ep: EncapsulatedPacket) {
        fun publicKey(): PublicKey {
            TODO()
        }
        val (payload, signature1) = ProtoBuf.decodeFromByteArray<PaymentDto>(ep.dataBytes)
        val signature = Signature.getInstance("SHA512withECDSA", "BC")
        signature.initVerify(publicKey())
        signature.update(signature1)
        if (!signature.verify(ProtoBuf.encodeToByteArray(payload))) {
            throw RuntimeException(/*TODO*/)
        }

        val (n3_, n4, coin) = payload
        val cipher = Cipher.getInstance("ECIES", "BC")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey())
        val cipher2 = Cipher.getInstance("ECIES", "BC")
        cipher2.init(Cipher.ENCRYPT_MODE, publicKey())
        val proxyPayload =
            ProtoBuf.encodeToByteArray(
                TicketCredentialsDto.Payload.Content(
                    "ip",
                    12,
                    "movie",
                    Settings.getSettingsFromFile("file"),
                    n4 + 1
                )
            )
        val streamingPayload =
            ProtoBuf.encodeToByteArray(
                TicketCredentialsDto.Payload.Content(
                    "ip",
                    12,
                    "movie",
                    Settings.getSettingsFromFile("file"),
                    SecureRandom().nextInt()
                )
            )
        val payload1 = TicketCredentialsDto.Payload(cipher.doFinal(proxyPayload), cipher2.doFinal(streamingPayload))

        fun privateKey(): PrivateKey {
            TODO()
        }

        val privateSignature = Signature.getInstance("SHA512withECDSA", "BC")
        privateSignature.initSign(privateKey())
        privateSignature.update(ProtoBuf.encodeToByteArray(payload1))
        val signature2 = privateSignature.sign()
        val out = ProtoBuf.encodeToByteArray(TicketCredentialsDto(payload1, signature2))
        val ep = EncapsulatedPacket(out, out.size, 6) //TODO version needs to be parameterized hmac also broken
        outSocket.send(DatagramPacket(ep.data, ep.data.size, ep.from, ep.port))
    }

    fun processMessage(p: DatagramPacket) {
        val ep = EncapsulatedPacket(p)
        val hello = 1
        val authentication = 3
        val payment = 5
        when (ep.msgType.toInt()) {
            hello -> sendAuthenticationRequest(ep)
            authentication -> sendPaymentRequest(ep)
            payment -> sendTicketCredentials(ep)
            9 -> throw RuntimeException(/*TODO*/)
            else -> throw RuntimeException(/*TODO*/)
        }
    }

}