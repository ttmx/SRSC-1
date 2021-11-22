package proxy

import coins.CoinsRepository
import users.UsersRepository
import java.net.DatagramSocket
import java.net.SocketAddress

class Authentication(socketAddress: SocketAddress) {

    val outSocket = DatagramSocket()
    val users = UsersRepository()
    val coins = CoinsRepository()

    fun getStreamInfo(userId: String, password: String, proxyBoxId: String, coinId: String) {
        val authUser = users.authUser(userId, password)
        val coin = coins.getCoin(coinId)
        sendHello(userId, proxyBoxId)

    }

    private fun sendHello(userId: String, proxyBoxId: String) {
        TODO("Not yet implemented")
    }


}