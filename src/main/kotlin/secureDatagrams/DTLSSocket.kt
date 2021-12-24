package secureDatagrams

import java.net.SocketAddress
import java.net.DatagramSocket
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLContext
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManagerFactory
import java.io.FileInputStream
import javax.net.ssl.SSLEngineResult.HandshakeStatus
import java.lang.Runnable
import java.net.DatagramPacket
import java.nio.ByteBuffer
import java.util.*

// This is a reference / suggestion or guideline showing the
// principle for an implementation of a DTLS Socket, to be used
// for general purpose DTLS support over Datagram Sockets (UDP)
// You wil need some imports ... not very different from the TLS/TCP case
class DTLSSocket(private val ksTrustPath: String,private val ksKeysPath:String, dtlsConfig: Properties, is_server: Boolean, address: SocketAddress) :
    DatagramSocket(address) {
    private val engine // The SSLEngine
            : SSLEngine



    init {

        // for the following configs, take a look on exemplified
        // dtls config files ... Possibly you have other interesting
        // config support - json, xml or whatever ... would be great ;-)
        val protocol = dtlsConfig.getProperty("TLS-PROT-ENF")
        engine = createSSLContext().createSSLEngine()
        if (is_server) //server endpoint
            setServerAuth(dtlsConfig.getProperty("TLS-AUTH")) else  // client endpoint
            setProxyAuth(dtlsConfig.getProperty("TLS-AUTH"))

        // and for both ... In this way I have a common way to
        // have common enabled ciphersuites for sure ...
        // But you can decide to try with different csuites for each side
        // but don't forget ... ou must have something in common
        // The same for protocol versions you want to enable
        engine.enabledCipherSuites = dtlsConfig.getProperty("CIPHERSUITES").split(",").toTypedArray()
        engine.enabledProtocols = arrayOf(protocol)
    }

    // Now let's go to make the SSL context (w/ SSL Context class)
    // See JSSE Docs and class slides
    private fun createSSLContext(): SSLContext {

        // Need a SSLContext for DTLS (see above)
        val sslContext = SSLContext.getInstance(SSL_CONTEXT)

        // Keystores and trusted stores that will be used according to
        // the required configurations ...
        val ksKeys = KeyStore.getInstance("PKCS12")
        val ksTrust = KeyStore.getInstance("PKCS12")
        val kmf = KeyManagerFactory.getInstance("SunX509")
        val tmf = TrustManagerFactory.getInstance("SunX509")

        // Now load the contents from keystores ...
        // they are in config paths used here as arguments
        // also need to express pwds protecting keystores and entries
        //
        // Of course you can also manage this in a different way - ex.,
        // passing the keystores etc ... as properties for the JVM runtime
        // as you can see in Lab examples using TLS / TCP (SSLSockets)
        //TODO hardcoded keys?
        ksKeys.load(
            FileInputStream(ksKeysPath),
            "password".toCharArray()
        )
        ksTrust.load(
            FileInputStream(ksTrustPath),
            "password".toCharArray()
        )
        kmf.init(ksKeys, "password".toCharArray())
        tmf.init(ksTrust)
        sslContext.init(kmf.keyManagers, tmf.trustManagers, null)

        // Now I return my "parameterized" sslContext ...
        return sslContext
    }

    // Now this is a little trick: depending on the configs, I will say to
    // the DTLS endpoints who is the server and who is the client
    // depending on who is the final app code using my DTLSockets
    // If the streamserver wants to be the DTLS server side in the handshake
    // the proxy will be the DTLS client ... or viceversa
    // Note that because I want to be able to support also client-only
    // authentication the trick here is to use server-only authentication and
    // invert the roles, with the proxy taking the DTLS server side ;-)
    // see the involved methods in JSSE documentation (SSLEngine class)
    // Ok ... If I am the proxy... 
    private fun setProxyAuth(authType: String) {
        when (authType) {
            MUTUAL, SERVER ->                 // I, proxy will be the DTLS client endpoint
                engine.useClientMode = true
            PROXY -> {
                // I, proxy will be the DTLS server endpoint
                // not requiring the server side authentication
                engine.useClientMode = false
                engine.needClientAuth = false
            }
        }
    }

    // If I am the streamserver ...
    private fun setServerAuth(authType: String) {
        when (authType) {
            MUTUAL -> {
                // I streamserver will act as the DTLS server side
                engine.useClientMode = false
                // But will require the client side authentication
                engine.needClientAuth = true
            }
            SERVER -> {
                // I stream server will be the DTLS server side
                engine.useClientMode = false
                // and will not require the client side authentication
                engine.needClientAuth = false
            }
            PROXY ->                 // I streamserver will work as the DTLS client side
                engine.useClientMode = true
        }
    }

    // Now the remaining is the "conventional" code from the DTLS-enabled
    // handshake ... See the JSSE Documentation ...
    private fun runTasks(): HandshakeStatus {
        var runnable: Runnable
        while (engine.delegatedTask.also { runnable = it } != null) {
            runnable.run()
        }
        return engine.handshakeStatus
    }

    // unwrap received TLS msg types and contents
    private fun unwrap(): HandshakeStatus {
        val session = engine.session
        val outBuffer = ByteBuffer.allocate(session.packetBufferSize)
        super.receive(DatagramPacket(outBuffer.array(), 0, outBuffer.capacity()))
        return engine.unwrap(outBuffer, ByteBuffer.allocate(session.applicationBufferSize)).handshakeStatus
    }

    // wrap TLS msg types and contents
    private fun wrap(address: SocketAddress): HandshakeStatus {
        val session = engine.session
        val outBuffer = ByteBuffer.allocate(session.packetBufferSize)
        val status = engine.wrap(ByteBuffer.allocate(session.applicationBufferSize), outBuffer).handshakeStatus
        super.send(DatagramPacket(outBuffer.array(), 0, outBuffer.position(), address))
        return status
    }

    // unwrap if needed again received TLS msg types and contents
    private fun unwrapAgain(): HandshakeStatus {
        val session = engine.session
        return engine.unwrap(
            ByteBuffer.allocate(session.packetBufferSize),
            ByteBuffer.allocate(session.applicationBufferSize)
        ).handshakeStatus
    }

    // Begin the TLS handshake
    fun beginHandshake(address: SocketAddress) {
        engine.beginHandshake()
        var status = engine.handshakeStatus
        while (status != HandshakeStatus.NOT_HANDSHAKING && status != HandshakeStatus.FINISHED) {
            status = when (status) {
                HandshakeStatus.NEED_TASK -> runTasks()
                HandshakeStatus.NEED_WRAP -> wrap(address)
                HandshakeStatus.NEED_UNWRAP -> unwrap()
                HandshakeStatus.NEED_UNWRAP_AGAIN -> unwrapAgain()
                else -> break
            }
        }
    }

    // Now is up to you ... and your previous protocols you have for
    // tunneling the packets on top of your DTLS/UDP Sockets
    // In the suggestion I can have protocol handlers to manage any
    // protocol I want to encapsulate as tunneled traffic in  my DTLS Channels
    // So I can have SRTSP or even SAPKDP if implemented in Datagram Sockets
    // which is possibly not your case ...
    // My protocol handlers here are SRTSPProtocol class or SAPKDPProtocol class
    // ... Anyway you must manage this according to your previous PA#1 implement.

//    fun send(packet: DatagramPacket?, srtsp: SRTSPProtocol) {
//        srtsp.createPacket(packet) //SRTSP packet as the DTLS packet payload
//        super.send(packet)
//    }
//
//    fun receive(packet: DatagramPacket?, srtsp: SRTSPProtocol?) {
//        // etc ...
//    }
//
//    fun send(packet: DatagramPacket?, sapkdp: SAPKDPProtocol) {
//        sapkdp.createPacket(packet) //SAPKDP packet as the DTLS packet payload
//        super.send(packet)
//    }
//
//    fun receive(packet: DatagramPacket?, ssp: SSPProtocol?) {
//
//        // etc ...
//    }

    //   What of you want to encrypt a DatagramPacket and send over the
    //   DTLS Engine  (wrap) ... or to receive an encrypted DatagramPacket
    //   from a DTLS Engine (unwrap)
    private fun encrypt(packet: DatagramPacket) {
        var buffer = ByteArray(packet.length)
        System.arraycopy(packet.data, 0, buffer, 0, packet.length)
        val inBuffer = ByteBuffer.wrap(buffer)
        val outBuffer = ByteBuffer.allocate(engine.session.packetBufferSize)
        engine.wrap(inBuffer, outBuffer)
        buffer = ByteArray(outBuffer.position())
        System.arraycopy(outBuffer.array(), 0, buffer, 0, outBuffer.position())
        packet.setData(buffer, 0, buffer.size)
    }

    private fun decrypt(packet: DatagramPacket): Int {
        val buffer = ByteArray(packet.length)
        System.arraycopy(packet.data, 0, buffer, 0, packet.length)
        val inBuffer = ByteBuffer.wrap(buffer)
        val outBuffer = ByteBuffer.allocate(engine.session.packetBufferSize)
        val bytesProduced = engine.unwrap(inBuffer, outBuffer).bytesProduced()
        if (bytesProduced == 0) return 0
        System.arraycopy(outBuffer.array(), 0, packet.data, 0, outBuffer.position())
        packet.length = outBuffer.position()
        return bytesProduced
    }

    companion object {
        // In this case I will take the possibility for different configs
        // of DTLS endpoints ...
        private const val MUTUAL = "MUTUAL"
        private const val PROXY = "PROXY" //client side
        private const val SERVER = "SSERVER" //server side
        private const val SSL_CONTEXT = "DTLS"
    }


}