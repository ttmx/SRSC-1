package secureDatagrams

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

class CryptoTools {
    companion object{


         fun checkSignature(dataB64:String,signatureB64 :String){
            val signature = Base64.getDecoder().decode(signatureB64)
            val ecdsaVerify: Signature = Signature.getInstance(Settings.signatureAlgorithm)
            val publicKeySpec: EncodedKeySpec =
                X509EncodedKeySpec(Base64.getDecoder().decode(Settings.publicKeySS))

            val keyFactory = KeyFactory.getInstance("EC")
            val publicKey = keyFactory.generatePublic(publicKeySpec)

            ecdsaVerify.initVerify(publicKey)
            ecdsaVerify.update(Base64.getDecoder().decode(dataB64))
            if(!ecdsaVerify.verify(signature)){
                throw InvalidSignatureException()
            }
        }
    }
}