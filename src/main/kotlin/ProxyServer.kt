import java.io.FileInputStream
import java.io.FileNotFoundException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.util.*
import kotlin.system.exitProcess

fun main() {
    lateinit var inputStream: FileInputStream
    try {
        inputStream = FileInputStream("config.properties")
    } catch (e: FileNotFoundException) {
        println("Configuration file not found!")
        exitProcess(1)
    }


    val properties = Properties()
    properties.load(inputStream)
    val remote = properties.getProperty("remote")
    val destinations = properties.getProperty("localdelivery")
    val inSocketAddress: SocketAddress = parseSocketAddress(remote)
    val outSocketAddressSet = destinations.split(",").map { s: String -> parseSocketAddress(s) }.toSet()
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
    val split = socketAddress.split(":")
    val host = split[0]
    val port = split[1].toInt()
    return InetSocketAddress(host, port)
}