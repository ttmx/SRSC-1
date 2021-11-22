package users

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.io.FileInputStream
import java.io.FileNotFoundException
import kotlin.system.exitProcess

class UsersRepository {
    private val users = HashMap<String, User>()

    init {
        users["user"] = User("user", "password") //TODO hash
        val inputString: String = try {
            FileInputStream("users.json").reader().readText()
        } catch (e: FileNotFoundException) {
            System.err.println("Configuration file not found!")
            exitProcess(1)
        }
        val userData = Json.decodeFromString<MutableList<User>>(inputString)

        for (u in userData){
            users[u.userId] = u
        }
    }

    fun authUser(userId: String, password: String): User {

        val user = users[userId] ?: throw RuntimeException("User not found!")
        if (user.password == password) {
            return user
        } else {
            throw RuntimeException("Wrong password!")
        }
    }
}