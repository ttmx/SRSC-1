package secureDatagrams

import kotlinx.serialization.json.Json

class SADKDPPacket {
    data class Hello(val userId: String, val proxyBoxId: String)

    data class AuthenticationRequest(val n1:String,val salt:String,val counter:Int)
    init {
    }
}