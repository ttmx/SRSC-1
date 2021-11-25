package sadkdp.auth

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.protobuf.ProtoBuf
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import javax.crypto.Cipher

class AuthHelper {
    @ExperimentalSerializationApi
    companion object {
        inline fun <reified T> sign(dto: T, privateKey: PrivateKey): ByteArray {
            val signer = Signature.getInstance("SHA512withECDSA", "BC")
            signer.initSign(privateKey, SecureRandom())
            signer.update(ProtoBuf.encodeToByteArray(dto))
            return signer.sign()
        }

        inline fun <reified T> verify(dto: T, signature1: ByteArray, publicKey: PublicKey) {
            val verifier = Signature.getInstance("SHA512withECDSA", "BC")
            verifier.initVerify(publicKey)
            verifier.update(ProtoBuf.encodeToByteArray(dto))
            if (!verifier.verify(signature1)) {
                throw RuntimeException("Invalid Signature")
            }
        }

        inline fun <reified T> encrypt(dto: T, publicKey: PublicKey): ByteArray {
            val cipher = Cipher.getInstance("ECIES", "BC")
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
            return cipher.doFinal(ProtoBuf.encodeToByteArray(dto))
        }

        inline fun <reified T> decrypt(payload: ByteArray, privateKey: PrivateKey): T {
            val cipher = Cipher.getInstance("ECIES", "BC")
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
            return ProtoBuf.decodeFromByteArray(cipher.doFinal(payload))
        }
    }
}