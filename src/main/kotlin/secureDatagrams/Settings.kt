package secureDatagrams

import java.io.FileInputStream
import java.io.FileNotFoundException
import java.util.*
import kotlin.system.exitProcess

class Settings {
    companion object{
        //TODO Setup keys

        val publicKeySS = ByteArray(2)
        private val inputStream: FileInputStream = FileInputStream("crypto.properties")
        private val properties = Properties()
        init {
            properties.load(inputStream)
        }
        val symmetricSuite: String = properties.getProperty("symmetric_suite")
        val symPassword: String = properties.getProperty("sym_password","")
        val iv: ByteArray = properties.getProperty("iv","AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").decodeHex()
        val hmacSuite: String = properties.getProperty("hmac_suite")
        val hmacKey = properties.getProperty("hmac_key").decodeHex()

        private fun String.decodeHex(): ByteArray {
            check(length % 2 == 0) { "Must have an even length" }

            return chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
        }

        const val signatureAlgorithm = "SHA256withECDSA"
    }

}