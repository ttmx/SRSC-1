package secureDatagrams

import java.io.FileInputStream
import java.io.FileNotFoundException
import java.util.*
import kotlin.system.exitProcess

class Settings {
    companion object{
        //TODO Setup keys

        private val inputStream: FileInputStream = FileInputStream("crypto.properties")
        private val properties = Properties()
        val symmetric = properties.getProperty("symmetric")
        val destinations = properties.getProperty("localdelivery")


        const val signatureAlgorithm = "SHA256withECDSA"
        fun init(){
            val properties = Properties()
            properties.load(inputStream)
            val publicKeySS = ByteArray(2)
        }
    }
}