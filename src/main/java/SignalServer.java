import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Socket;
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
        Properties properties = new Properties();
        properties.load(inputStream);
        String userid = properties.getProperty("userid");
        String proxyboxid = properties.getProperty("proxyboxid");
        int port = Integer.parseInt(properties.getProperty("port"));
        DatagramSocket s = new DatagramSocket(port);
        Helper ss = new Helper(userid, proxyboxid, port, s);
        while (true) {
            byte[] buff = new byte[4096];
            DatagramPacket p = new DatagramPacket(buff, buff.length);
            s.receive(p);
            ss.processMessage(p);
        }
    }

    static class Helper {

        private final String userid;
        private final String proxyboxid;
        private final int port;
        private final DatagramSocket s;

        public Helper(String userid, String proxyboxid, int port, DatagramSocket s) {
            this.userid = userid;
            this.proxyboxid = proxyboxid;
            this.port = port;
            this.s = s;
        }

        private void processMessage(DatagramPacket p) {

        }

        private void doAuthentication(Socket s) {
            respondHello(s);

            respondAuthentication(s);

            respondPayment(s);
        }

        private void respondHello(Socket s) {
            //Todo
        }

        private void respondAuthentication(Socket s) {
            //TODO("Not yet implemented")
        }

        private void respondPayment(Socket s) {
            //TODO("Not yet implemented")
        }
    }
}
