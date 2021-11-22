package users

import kotlinx.serialization.Serializable

@Serializable
data class User(val userId: String, val password: String)
