package coins

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.io.File

class CoinsRepository {
    val coins:List<Coin> = Json.decodeFromString(File("config/proxy/coins.json").readText())


}