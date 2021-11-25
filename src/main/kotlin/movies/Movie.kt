package movies

import kotlinx.serialization.Serializable

@Serializable
data class Movie(val filmName: String, val fileName: String, val price: Int)
