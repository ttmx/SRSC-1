package sadkdp.dto

import kotlinx.serialization.Serializable

@Serializable
data class AuthenticationRequestDto(val n1: Int, val salt: String, val counter: Int)
