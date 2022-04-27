package org.pevs;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;

import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.Inet4NetworkAddress;
import org.pcap4j.util.NifSelector;

public class App {

    static PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;
        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;
    }


    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        // The code we had before
//        NifSelector nifSelector = new NifSelector();
        PcapNetworkInterface device = getNetworkDevice();
        System.out.println("You chose: " + device);

        // New code below here
        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        // Open the device and get a handle
        int snapshotLength = 65536; // in bytes //dlzka paketu v bytoch max
        int readTimeout = 500; // in milliseconds
        final PcapHandle handle;
        handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);

        // filter iba na port 80
//        BpfFilterBuilder bpf = new BpfFilterBuilder();
//        String filter = bpf.setFilter();

//        String filter = "port 80";
//        String filter = "dst host 239.255.255.250 || src host 192.168.1.6";//"dst host 192.168.1.6 || src host 192.168.1.6";//"tcp port 80";
//        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        // Create a listener that defines what to do with the received packets
        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                // Override the default gotPacket() function and process packet
//                IpV4Packet.IpV4Header ipV4Header = packet.get(IpV4Packet.class).getHeader();
//                System.out.println(handle.getTimestamp() + " " + ipV4Header.getSrcAddr() + " > " + ipV4Header.getDstAddr() +" : " + ipV4Header.getProtocol() + ipV4Header.getTotalLength());
//                IpV4Packet.IpV4Header ipV4Header = packet.get(IpV4Packet.class).getHeader();
                //System.out.println(ipV4Header.getSrcAddr() + " > " + ipV4Header.getDstAddr() +" : " + ipV4Header.getProtocol() + ipV4Header.getTotalLength());
                //System.out.println("cely packet" + packet);
//

                IpV4Packet.IpV4Header ipV4Header = packet.get(IpV4Packet.class).getHeader();
                System.out.println(handle.getTimestamp() + " "
                        + ipV4Header.getSrcAddr() + " > "
                        + ipV4Header.getDstAddr() + " : "
                        + ipV4Header.getProtocol() + " lenght: "
                        + ipV4Header.getTotalLength()
                    );

                //System.out.println(packet);
//                Packet.Header header =packet.getHeader();
//                short port_num = 80;
//                TcpPort httpPort = new TcpPort(port_num,"HTTP");
//                System.out.println(packet.get(TcpPacket.class).getHeader().getDstPort().equals(httpPort)
//                + "\n " + httpPort
//                + "\n " + packet.get(TcpPacket.class).getHeader().getDstPort());


//                if(packet.get(TcpPacket.class).getHeader().getDstPort().equals(httpPort) ||
//                        packet.get(TcpPacket.class).getHeader().getSrcPort().equals(httpPort)){
//
//                    //packet.get(IpV4Packet.class).getHeader().get
//                    //byte[] data = packet.get(IpV4Packet.class).getPayload().getRawData();
//                    byte[] data = packet.get(TcpPacket.class).getPayload().getRawData();
//                    String decoded = new String(data, StandardCharsets.UTF_8);
//                    System.out.println(decoded);
//                }


            }
        };

        // thread to break loop
        Thread t = new Thread(() -> {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            try {
                in.readLine();
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        });
        t.start();

        // Tell the handle to loop using the listener we created
        try {
            int maxPackets = -1;
            handle.loop(maxPackets, listener);
        } catch (InterruptedException e) {
            System.out.println("Zachytavanie zastavene");
            e.printStackTrace();
        }


        PcapStat stats = handle.getStats();
        System.out.println(stats.getNumPacketsReceived() + " " + stats.getNumPacketsDropped() + " " + stats.getNumPacketsCaptured());

        // Cleanup when complete
        handle.close();
    }

}
