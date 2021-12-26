package secureDatagrams

import java.io.FileInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketAddress
import java.nio.ByteBuffer
import java.security.KeyStore
import java.util.*
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult.HandshakeStatus
import javax.net.ssl.TrustManagerFactory

// This is a reference / suggestion or guideline showing the
// principle for an implementation of a DTLS Socket, to be used
// for general purpose DTLS support over Datagram Sockets (UDP)
// You wil need some imports ... not very different from the TLS/TCP case
open class DTLSSocket//server endpoint
// client endpoint
    (
    private val ksTrustPath: String,
    private val ksKeysPath: String,
    dtlsConfig: Properties,
    is_server: Boolean,
    address: SocketAddress
) :
    DatagramSocket(address) {

    private val engine // The SSLEngine
            : SSLEngine


    init {
        println("DTLS Config: $dtlsConfig")
        val protocol = dtlsConfig.getProperty("tlsVersion")
        engine = createSSLContext().createSSLEngine()
        if (is_server) //server endpoint
            setServerAuth(dtlsConfig.getProperty("authentication")) else  // client endpoint
            setProxyAuth(dtlsConfig.getProperty("authentication"))
        engine.enabledCipherSuites = dtlsConfig.getProperty("ciphersuites").split(",").toTypedArray()
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
        var runnable: Runnable?
        while (engine.delegatedTask.also { runnable = it } != null) {
            runnable?.run()
        }
        return engine.handshakeStatus
    }

    // unwrap received TLS msg types and contents
    private fun unwrap(): Pair<HandshakeStatus, SocketAddress> {
        val session = engine.session
        val outBuffer = ByteBuffer.allocate(session.packetBufferSize)
        val p = DatagramPacket(outBuffer.array(), 0, outBuffer.capacity())
        super.receive(p)
//        println("Got  ${String(p.data,0,p.length)} in unwrap")
        val bb = ByteBuffer.allocate(session.applicationBufferSize)
        val k = engine.unwrap(outBuffer, bb)

//        println(k.status)
//        println("Got  ${String(bb.array(),0,p.length)} in unwrap")
        return Pair(k.handshakeStatus, p.socketAddress)
    }

    // wrap TLS msg types and contents
    private fun wrap(address: SocketAddress): HandshakeStatus {
        val session = engine.session
        val outBuffer = ByteBuffer.allocate(session.packetBufferSize)
        val s = engine.wrap(ByteBuffer.allocate(session.applicationBufferSize), outBuffer)
        val status = s.handshakeStatus
        super.send(DatagramPacket(outBuffer.array(), 0, outBuffer.position(), address))

//        println("Sent ${String(outBuffer.array(),0,outBuffer.position())} in wrap")
//        println(s.status)
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
    fun doHandshake(add: SocketAddress?) {
        var address = add
        if (engine.handshakeStatus != HandshakeStatus.FINISHED) {
            engine.beginHandshake()
        } else {
            return
        }
        var status = engine.handshakeStatus
        while (status != HandshakeStatus.NOT_HANDSHAKING && status != HandshakeStatus.FINISHED) {
//            println("We shaking at $status with $address")
            status = when (status) {
                HandshakeStatus.NEED_TASK -> runTasks()
                HandshakeStatus.NEED_WRAP -> wrap(address!!)
                HandshakeStatus.NEED_UNWRAP -> unwrap().also { address = it.second }.first
                HandshakeStatus.NEED_UNWRAP_AGAIN -> unwrapAgain()
                else -> break
            }
        }
        println("Finished shaking")
    }

    // Now is up to you ... and your previous protocols you have for
    // tunneling the packets on top of your DTLS/UDP Sockets
    // In the suggestion I can have protocol handlers to manage any
    // protocol I want to encapsulate as tunneled traffic in  my DTLS Channels
    // So I can have SRTSP or even SAPKDP if implemented in Datagram Sockets
    // which is possibly not your case ...
    // My protocol handlers here are SRTSPProtocol class or SAPKDPProtocol class
    // ... Anyway you must manage this according to your previous PA#1 implement.

    override fun send(p: DatagramPacket) {
//        beginHandshake(p.socketAddress)
//        while (engine.handshakeStatus != HandshakeStatus.FINISHED &&
//            engine.handshakeStatus != HandshakeStatus.NOT_HANDSHAKING &&
//            !engine.isInboundDone &&
//            !engine.isOutboundDone
//        ) {
//            Thread.sleep(100)
//            println("send loop")
//        }

//        println("Sent ${p.length}\n---\n ${String(p.data,0,p.length)}\n==========================")
        encrypt(p)

//        println("SentEnc ${p.length}\n---\n ${String(p.data,0,p.length)}\n==========================")
        super.send(p)
    }

    override fun receive(p: DatagramPacket) {
//        beginHandshake(null)
//        while (engine.handshakeStatus != HandshakeStatus.FINISHED &&
//            engine.handshakeStatus != HandshakeStatus.NOT_HANDSHAKING &&
//            !engine.isInboundDone &&
//            !engine.isOutboundDone
//        ) {
//            Thread.sleep(100)
//            println("recv loop")
//        }
        var ctHash:Int? = null
        var ptHash:Int? = null
        // if data wasn't actually decrypted, get a new block, it was probably tls garbage
        while (ctHash == ptHash) {
            super.receive(p)
            ctHash = p.data.contentHashCode()
//            println("RecvEnc ${p.length}\n---\n ${String(p.data,0,p.length)}\n==========================")
            decrypt(p)
            ptHash = p.data.contentHashCode()
//            println("Recv ${p.length}\n---\n ${String(p.data,0,p.length)}\n==========================")
        }
    }

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

    //   What if you want to encrypt a DatagramPacket and send over the
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