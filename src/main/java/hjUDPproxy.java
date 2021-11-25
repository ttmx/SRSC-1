/* hjUDPproxy, 20/Mar/18
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import coins.CoinsRepository;
import kotlin.Triple;
import org.jetbrains.annotations.NotNull;
import rtstp.RTSTPNegotiatorClient;
import sadkdp.auth.AuthClient;
import sadkdp.dto.TicketCredentialsDto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class hjUDPproxy {
    public static void main(String[] args) throws Exception {
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream("config/proxy/config.properties");
        } catch (FileNotFoundException e) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Properties properties = new Properties();
        properties.load(inputStream);
        String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");

        String signal = properties.getProperty("signal");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(","))
                .map(hjUDPproxy::parseSocketAddress)
                .collect(Collectors.toSet());

        System.out.print("Starting proxy server");
        AuthClient auth = new AuthClient(
                new CoinsRepository(),
                inSocketAddress,
                parseSocketAddress(signal),
                getKeyStoreFromFile("PKCS12", "config/proxy/proxy.p12", "password")
        );
        Triple<TicketCredentialsDto.Payload, byte[], byte[]> streamInfo = auth.getStreamInfo("user", "password", "proxyBoxId", "coinId", "cars");
        DatagramSocket inSocket = new RTSTPNegotiatorClient(streamInfo, parseSocketAddress(properties.getProperty("streaming"))).negotiate();
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];


        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket); // if remote is unicast

            System.out.print("*");
            for (SocketAddress outSocketAddress : outSocketAddressSet) {
                outSocket.send(new DatagramPacket(inPacket.getData(), inPacket.getLength(), outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }

    @NotNull
    private static KeyStore getKeyStoreFromFile(String type, String fileName, String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(type);
        FileInputStream stream = new FileInputStream(fileName);
        keyStore.load(stream, password.toCharArray());
        return keyStore;
    }
}
