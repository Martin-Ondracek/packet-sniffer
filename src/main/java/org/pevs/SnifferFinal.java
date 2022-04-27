package org.pevs;

import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.NifSelector;
import picocli.CommandLine;
import picocli.CommandLine.Option;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Callable;

public class SnifferFinal implements Callable<Integer> {

    @Option(names = {"-f", "--filter"}, description = "Set desired BPF filter, please use '-' instead of space")
    private String filter;

    @Option(names = {"-w", "--write"}, description = "Write captured packets to out.pcap file")
    private boolean write;

    @Option(names = {"-o", "--output"}, description = "Display captured packets")
    private boolean output;

    @Option(names = {"-d", "--decode"}, description = "Output HTTP packets with decoded payload")
    private boolean decode;

    @Option(names = {"-c", "--count"}, description = "Number of packets to be captured")
    private String count;

    @Option(names = { "-h", "--help" }, usageHelp = true, description = "Display a help message")
    private boolean helpRequested;

    static short port_num = 80;
    static TcpPort httpPort = new TcpPort(port_num,"HTTP");

    static PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;
        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;
    }

    public Integer call() throws PcapNativeException, NotOpenException {
        //Select network device to capture on
        PcapNetworkInterface device = getNetworkDevice();
        System.out.println("You chose: " + device);

        // If no device - exit
        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        // Open the device and get a handle
        int snapshotLength = 65536; //frame max length in bytes
        int readTimeout = 500; // in milliseconds
        final PcapHandle handle;
        handle = device.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
        final PcapDumper dumper = write ? handle.dumpOpen("out.pcap") : null;

        //Set filter if applied
        if(filter != null){
            filter = filter.replace('-',' ');
            try {
                handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            }catch (PcapNativeException e){
                System.out.println("Unknown filter");
                System.exit(1);
            }

        }

        // Create a listener that defines what to do with the received packets
        PacketListener listener = packet -> {

            if(output){
                IpV4Packet.IpV4Header ipV4Header = packet.get(IpV4Packet.class).getHeader();
                System.out.println(handle.getTimestamp() + " "
                        + ipV4Header.getSrcAddr() + " > "
                        + ipV4Header.getDstAddr() + " : "
                        + ipV4Header.getProtocol() + " length: "
                        + packet.length()
                    );
            }

            if (write && dumper != null && output) {
                try {
                    dumper.dump(packet, handle.getTimestamp());
                } catch (NotOpenException e) {
                    e.printStackTrace();
                }
            }

            if (decode){
                if(packet.get(TcpPacket.class).getHeader().getDstPort().equals(httpPort)
                    || packet.get(TcpPacket.class).getHeader().getSrcPort().equals(httpPort)){

                    byte[] data = packet.get(TcpPacket.class).getPayload().getRawData();
                    String decoded = new String(data, StandardCharsets.UTF_8);
                    System.out.println(decoded);
                }
           }

        };

        // thread to break loop if no count specified
        if(count == null){
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
        }

        // Tell the handle to loop using the listener or dumper
        try {
            int maxPackets = (count == null) ? -1 : Integer.parseInt(count);
            if ((!output && write)) {
                handle.loop(maxPackets, dumper);
            } else {
                handle.loop(maxPackets, listener);
            }

        } catch (InterruptedException e) {
            System.out.println("Packet capturing finished");
        }

        // Cleanup when complete
        if (write && dumper != null){
            dumper.close();
        }
        handle.close();

        return 0;
    }

    public static void main(String[] args) {
        int rc = new CommandLine(new SnifferFinal()).execute(args);
        System.exit(rc);
    }

}
