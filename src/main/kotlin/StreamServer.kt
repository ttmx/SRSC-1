import secureDatagrams.SecureDatagramSocket
import java.io.DataInputStream
import java.io.FileInputStream
import java.net.DatagramPacket
import java.net.InetSocketAddress
import kotlin.math.max
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    if (args.size != 3) {
        println("Erro, usar: mySend <movie> <ip-multicast-address> <port>")
        println("        or: mySend <movie> <ip-unicast-address> <port>")
        exitProcess(-1)
    }
    var size: Int
    var count = 0
    var time: Long
    val g = DataInputStream(FileInputStream(args[0]))
    val buff = ByteArray(4096)
    val s = SecureDatagramSocket()
    val addr = InetSocketAddress(args[1], args[2].toInt())
    val p = DatagramPacket(buff, buff.size, addr)
    val t0 = System.nanoTime() // tempo de referência para este processo
    var q0: Long = 0
    while (g.available() > 0) {
        size = g.readShort().toInt()
        time = g.readLong()
        if (count == 0) q0 = time // tempo de referência no stream
        count += 1
        g.readFully(buff, 0, size)
        p.setData(buff, 0, size)
        p.socketAddress = addr
        val t = System.nanoTime()
        Thread.sleep(max(0, (time - q0 - (t - t0)) / 1000000))

        // send packet (with a frame payload)
        // Frames sent in clear (no encryption)
        s.send(p)
        print(".")
    }
    println("DONE! all frames sent: $count")
}