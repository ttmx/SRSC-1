import secureDatagrams.DTLSSocket
import java.io.FileInputStream
import java.net.InetSocketAddress
import java.util.*

fun main(args: Array<String>) {
    lateinit var s: DTLSSocket
    if (args.size == 1) {
        val inputStream = FileInputStream("config/proxy/dtls.properties")
        val p = Properties()
        p.load(inputStream)
        s = DTLSSocket("config/trustbase.p12", "config/proxy/selftls.p12", p, false, InetSocketAddress(4433))

        s.beginHandshake(InetSocketAddress("localhost", 4434))
    } else {

        val inputStream = FileInputStream("config/signal/dtls.properties")
        val p = Properties()
        p.load(inputStream)
        s = DTLSSocket("config/trustbase.p12", "config/signal/selftls.p12", p, true, InetSocketAddress(4434))

        s.beginHandshake(InetSocketAddress("localhost", 4433))
    }

}
