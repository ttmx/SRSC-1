package sadkdp.dto

import kotlinx.serialization.Serializable


@Serializable
data class HelloDto(val userId: String, val proxyBoxId: String)
