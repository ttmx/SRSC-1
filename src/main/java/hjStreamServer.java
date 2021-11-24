/*
 * hjStreamServer.java
 * Streaming server: streams video frames in UDP packets
 * for clients to play in real time the transmitted movies
 */

import secureDatagrams.SecureDatagramSocket;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.Security;

class hjStreamServer {

    static public void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("Erro, usar: mySend <movie> <ip-multicast-address> <port>");
            System.out.println("        or: mySend <movie> <ip-unicast-address> <port>");
            System.exit(-1);
        }
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        int size;
        int csize = 0;
        int count = 0;
        long time;
        DataInputStream g = new DataInputStream(new FileInputStream(args[0]));
        byte[] buff = new byte[4096];

        DatagramSocket s = new SecureDatagramSocket("stream");
        InetSocketAddress addr = new InetSocketAddress(args[1], Integer.parseInt(args[2]));
        DatagramPacket p = new DatagramPacket(buff, buff.length, addr);
        long t0 = System.nanoTime(); // Ref. time
        long q0 = 0;

        // Movies are encoded in .dat files, where each
        // frame is encoded in a real-time sequence of MP4 frames
        // Somewhat an FFMPEG4 playing scheme .. Dont worry

        // Each frame has:
        // Short size || Long Timestamp || byte[] EncodedMP4Frame
        // You can read (frame by frame to transmit ...
        // But you must folow the "real-time" encoding conditions

        // OK let's do it !

        while (g.available() > 0) {

            size = g.readShort(); // size of the frame
            csize = csize + size;
            time = g.readLong(); // timestamp of the frame
            if (count == 0)
                q0 = time; // ref. time in the stream
            count += 1;
            g.readFully(buff, 0, size);
            p.setData(buff, 0, size);
            p.setSocketAddress(addr);

            long t = System.nanoTime(); // what time is it?

            // Decision about the right time to transmit
            Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));

            // send datagram (udp packet) w/ payload frame)
            // Frames sent in clear (no encryption)

            s.send(p);

            // Just for awareness ... (debug)

            System.out.print(".");
        }

        long tend = System.nanoTime(); // "The end" time
        System.out.println();
        System.out.println("DONE! all frames sent: " + count);

        long duration = (tend - t0) / 1000000000;
        System.out.println("Movie duration " + duration + " s");
        System.out.println("Throughput " + count / duration + " fps");
        System.out.println("Throughput " + (8 * (csize) / duration) / 1000 + " Kbps");

    }
}
