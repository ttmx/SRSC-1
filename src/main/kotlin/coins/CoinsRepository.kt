package coins

import kotlinx.datetime.LocalDate

class CoinsRepository {
    private val coins = HashMap<String, Coin>()

    init {
        coins["coinId"] = Coin(
            "coinId",
            "bank",
            25,
            LocalDate(2022, 2, 1),
            ByteArray(2),
            ByteArray(0),
            ByteArray(0),
            ByteArray(0),
            ByteArray(0)
        )
//        println(String(ProtoBuf.encodeToByteArray(coins["coinId"])))
    }

    fun getCoin(coinId: String): Coin {
        return coins[coinId] ?: throw RuntimeException("Coin not found!")
    }

}