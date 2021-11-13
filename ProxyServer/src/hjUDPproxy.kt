import java.io.FileInputStream
import kotlin.Throws
import kotlin.jvm.JvmStatic
import java.io.InputStream
import java.lang.Exception
import java.util.Properties
import java.net.SocketAddress
import java.util.Arrays
import java.net.InetSocketAddress
import java.util.stream.Collectors
import java.net.DatagramSocket
import java.net.DatagramPacket

internal object hjUDPproxy {
    @Throws(Exception::class)
    @JvmStatic
    fun main(args: Array<String>) {
        val inputStream: InputStream = FileInputStream("config.properties")
        if (inputStream == null) {
            System.err.println("Configuration file not found!")
            System.exit(1)
        }
        val properties = Properties()
        properties.load(inputStream)
        val remote = properties.getProperty("remote")
        val destinations = properties.getProperty("localdelivery")
        val inSocketAddress: SocketAddress = parseSocketAddress(remote)
        val outSocketAddressSet =
            Arrays.stream(destinations.split(",".toRegex()).toTypedArray()).map { s: String -> parseSocketAddress(s) }
                .collect(Collectors.toSet())
        val inSocket = DatagramSocket(inSocketAddress)
        val outSocket = DatagramSocket()
        val buffer = ByteArray(4 * 1024)
        while (true) {
            val inPacket = DatagramPacket(buffer, buffer.size)
            inSocket.receive(inPacket) // if remote is unicast
            print("*")
            for (outSocketAddress in outSocketAddressSet) {
                outSocket.send(DatagramPacket(buffer, inPacket.length, outSocketAddress))
            }
        }
    }

    private fun parseSocketAddress(socketAddress: String): InetSocketAddress {
        val split = socketAddress.split(":".toRegex()).toTypedArray()
        val host = split[0]
        val port = split[1].toInt()
        return InetSocketAddress(host, port)
    }
}