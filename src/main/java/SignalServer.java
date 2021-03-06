import movies.MoviesRepository;
import org.jetbrains.annotations.NotNull;
import sadkdp.auth.AuthServer;
import secureDatagrams.Settings;
import users.UsersRepository;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.KeyStore;
import java.security.Security;
import java.util.Properties;

public class SignalServer {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        AuthServer authServer = getAuthServer();
        authServer.startLoop();
    }

    private static int getPort() throws IOException {
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream("config/signal/signal.properties");
        } catch (FileNotFoundException e) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);
        return Integer.parseInt(properties.getProperty("port"));
    }

    @NotNull
    private static AuthServer getAuthServer() throws Exception {
        UsersRepository users = new UsersRepository("config/signal/users.json");
        MoviesRepository movies = new MoviesRepository("config/signal/movies.json");
        Settings settings = Settings.Companion.getSettingsFromFile("signal");
        KeyStore keyStore = getKeyStoreFromFile("PKCS12", "config/signal/signal.p12", "password");
        int listenPort = getPort();
        return new AuthServer(users, movies, settings, keyStore,listenPort);
    }

    @NotNull
    private static KeyStore getKeyStoreFromFile(String type, String fileName, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(type);
        FileInputStream stream = new FileInputStream(fileName);
        keyStore.load(stream, password.toCharArray());
        return keyStore;
    }

}
