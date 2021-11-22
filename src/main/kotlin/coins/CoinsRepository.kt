package coins

import java.time.LocalDate

class CoinsRepository {
    private val coins = HashMap<String, Coin>()

    init {
        coins["coinId"] = Coin(
            "coinId",
            "bank",
            25,
            LocalDate.of(2022, 2, 1),
            ByteArray(0),
            ByteArray(0),
            ByteArray(0),
            ByteArray(0),
            ByteArray(0)
        )
    }

    fun getCoin(coinId: String): Coin {
        return coins[coinId] ?: throw RuntimeException("Coin not found!")
    }

}