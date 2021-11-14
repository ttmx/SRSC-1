package secureDatagrams

class Settings {
    companion object{
        //TODO Setup keys
        val publicKeySS = ByteArray(2)
        const val signatureAlgorithm = "SHA256withECDSA"
    }
}