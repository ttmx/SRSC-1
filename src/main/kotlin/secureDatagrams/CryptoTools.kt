package secureDatagrams

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import java.util.stream.Collectors
import java.util.stream.IntStream
import javax.crypto.Mac
import kotlin.experimental.and
import kotlin.experimental.or


class CryptoTools {
    companion object {

        fun checkSignature(dataB64: String, signatureB64: String) {
            //TODO Redo this whole thing lmao
            val signature = Base64.getDecoder().decode(signatureB64)
            val ecdsaVerify: Signature = Signature.getInstance(Settings.signatureAlgorithm)
            val publicKeySpec: EncodedKeySpec =
                X509EncodedKeySpec(Base64.getDecoder().decode(Settings.publicKeySS))

            val keyFactory = KeyFactory.getInstance("EC")
            val publicKey = keyFactory.generatePublic(publicKeySpec)

            ecdsaVerify.initVerify(publicKey)
            ecdsaVerify.update(Base64.getDecoder().decode(dataB64))
            if (!ecdsaVerify.verify(signature)) {
                throw InvalidSignatureException()
            }
        }

        fun checkHmac(hMac: Mac, frame: ByteArray, receivedMac: ByteArray) {
            if (!MessageDigest.isEqual(hMac.doFinal(frame), receivedMac)) {
                throw IllegalStateException()
            }
        }

        fun makeHeader(version: Byte, msgType: Byte, len: Short): ByteArray {
            val versionAndType = version.toInt().shl(4).toByte() or (msgType and 0x01)
            return ByteBuffer.wrap(ByteArray(EncapsulatedPacket.HEADER_SIZE))
                .put(versionAndType)
                .putShort(len)
                .array()
        }

        fun BitSet.toBinaryString(): String? {
            return IntStream.range(0, length())
                .mapToObj { b: Int -> if (get(b)) "1" else "0" }
                .collect(Collectors.joining())
        }

    }
}