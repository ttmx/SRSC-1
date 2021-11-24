package sadkdp.dto

import kotlinx.serialization.Serializable

@Serializable
data class AuthenticationDto(val n1_: Int, val n2: Int, val movieId: String)
