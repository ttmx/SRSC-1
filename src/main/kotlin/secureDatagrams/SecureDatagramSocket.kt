package secureDatagrams

import java.net.DatagramSocket
import javax.crypto.Cipher

class SecureDatagramSocket(val encrypt: Cipher, val decrypt: Cipher) : DatagramSocket() {
    init {

    }
}