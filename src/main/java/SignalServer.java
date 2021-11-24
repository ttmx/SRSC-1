import users.UsersRepository;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.Security;
import java.util.Properties;

public class SignalServer {

    public static void main(String[] args) throws Exception {
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream("signal.properties");
        } catch (FileNotFoundException e) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Properties properties = new Properties();
        properties.load(inputStream);
        String userid = properties.getProperty("userid");
        String proxyboxid = properties.getProperty("proxyboxid");
        int port = Integer.parseInt(properties.getProperty("port"));
        DatagramSocket s = new DatagramSocket(port);
        UsersRepository ur = new UsersRepository("users.json");
        signal.Authentication ss = new signal.Authentication();
        while (true) {
            byte[] buff = new byte[4096];
            DatagramPacket p = new DatagramPacket(buff, buff.length);
            s.receive(p);
            ss.processMessage(p);
        }
    }

}
