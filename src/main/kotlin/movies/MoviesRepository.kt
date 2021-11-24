package movies

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.io.FileInputStream
import java.io.FileNotFoundException
import kotlin.system.exitProcess

class MoviesRepository(fileName:String) {
    val movies = HashMap<String, Movie>()

    init {
        val inputString: String = try {
            FileInputStream(fileName).reader().readText()
        } catch (e: FileNotFoundException) {
            System.err.println("Configuration file not found!")
            exitProcess(1)
        }
        val userData = Json.decodeFromString<List<Movie>>(inputString)

        for (u in userData) {
            movies[u.filmName] = u
        }
    }

}