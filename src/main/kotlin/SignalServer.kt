import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.net.ServerSocket
import java.net.Socket
import java.util.*
import kotlin.system.exitProcess

fun main() = runBlocking {
    lateinit var inputStream: FileInputStream
    try {
        inputStream = FileInputStream("signal.properties")
    } catch (e: FileNotFoundException) {
        println("Configuration file not found!")
        exitProcess(1)
    }


    val properties = Properties()
    properties.load(inputStream)
    val userid = properties.getProperty("userid")
    val proxyboxid = properties.getProperty("proxyboxid")
    val port = properties.getProperty("port").toInt()
    val inSocket = ServerSocket(port)
    while (true) {
        val s = inSocket.accept()
        launch {
            SignalServer(userid, proxyboxid, port, s)
        }
    }
}

class SignalServer(val userid: String, val proxyboxid: String, val port: Int, s: Socket) {
    init {
        doAuthentication(s)

    }

    private fun doAuthentication(s: Socket) {
        respondHello(s)

        respondAuthentication(s)

        respondPayment(s)
    }

    private fun respondPayment(s: Socket) {
        TODO("Not yet implemented")
    }

    private fun respondAuthentication(s: Socket) {
        TODO("Not yet implemented")
    }

    private fun respondHello(s: Socket) {
        //Todo
    }
}