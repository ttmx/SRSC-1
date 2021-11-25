package secureDatagrams

import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.io.FileInputStream
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey


@Serializable
data class Settings(
    val algorithm: String,
    val symmetricSuite: String,
    val symPassword: String,
    var hmacSuite: String,
    private val ivHex: String?,
    private val hmacKeyHex: String
) {
    companion object {
        const val signatureAlgorithm = "SHA512withECDSA"
        fun getSettingsFromFile(serverType: String): Settings {
            return Json.decodeFromString(
                String(
                    FileInputStream("config/$serverType/crypto.json")
                        .readAllBytes()
                )
            )
        }
    }

    val key = genKey()

    val iv: ByteArray?
        get() = ivHex?.decodeHex()

    val hmacKey: ByteArray
        get() = hmacKeyHex.decodeHex()

    private fun genKey(): ByteArray {
        val kg = KeyGenerator.getInstance(algorithm)
        kg.init(SecureRandom(symPassword.toByteArray()))
        return kg.generateKey().encoded
    }

    private fun String.decodeHex(): ByteArray {
        check(length % 2 == 0) { "Must have an even length" }

        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}