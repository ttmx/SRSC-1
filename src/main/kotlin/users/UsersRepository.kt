package users

class UsersRepository {
    private val users = HashMap<String, User>()

    init {
        users["user"] = User("user", "password") //TODO hash
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