package org.pevs;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.NifSelector;
import picocli.CommandLine;
import picocli.CommandLine.Option;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class SnifferFinal implements Callable<Integer> {

    final Logger logger = new Logger();

    @Option(names = {"-f", "--filter"}, description = "Set desired BPF filter, please use '-' instead of space")
    private String filter;

    @Option(names = {"-w", "--write"}, description = "Write captured packets to out.pcap file")
    private boolean write;

    @Option(names = {"-o", "--output"}, description = "Display short version of captured packets")
    private boolean output;

    @Option(names = {"-p", "--packet"}, description = "Display all information about captured packets")
    private boolean paketFull;

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

    public Integer call() throws PcapNativeException, NotOpenException, InterruptedException {
        logger.logInfo("Starting packet sniffer with options:" +
                "\nFilter: " + filter +
                "\nWrite: " + write +
                "\nOutput: " + output +
                "\nDecode: " + decode +
                "\nCount: " + count);

        if (count != null){
            try {
                Integer.parseInt(count);
            }catch (NumberFormatException e){
                System.out.println("Wrong count number.");
                logger.logError("Wrong count number inserted: " + count + " - exit");
                System.exit(1);
            }
        }

        //Select network device to capture on
        PcapNetworkInterface device = getNetworkDevice();
        System.out.println("You chose: " + device);
        logger.logInfo("Device chosen " + device);

        // If no device - exit
        if (device == null) {
            System.out.println("No device chosen.");
            logger.logError("No device chosen - exit.");
            System.exit(1);
        }

        // Open the device and get a handle
        int snapshotLength = 65536;
        int readTimeout = 500;
        final PcapHandle handle;
        handle = device.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);
        logger.logInfo("Handle set up: " + handle);
        final PcapDumper dumper = write ? handle.dumpOpen("out.pcap") : null;
        logger.logInfo("Dumper set: " + !(dumper == null));

        //Set filter if applied
        if(filter != null){
            filter = filter.replace('-',' ');
            try {
                handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
            }catch (PcapNativeException e){
                System.out.println("Unknown filter");
                logger.logError("Unknown filter" + filter + " - exit.");
                System.exit(1);
            }
            logger.logInfo("Filter set: "+ handle.getFilteringExpression());
        }


        // Create a listener that defines what to do with the received packets
        PacketListener listener = packet -> {

            if(output){
                EthernetPacket.EthernetHeader ethernetHeader = packet.get(EthernetPacket.class).getHeader();

                if(packet.contains(IpV4Packet.class)){
                    IpV4Packet.IpV4Header ipV4Header = packet.get(IpV4Packet.class).getHeader();
                    System.out.println(handle.getTimestamp() + " Type " + ethernetHeader.getType() + " "
                            + ipV4Header.getSrcAddr() + " > "
                            + ipV4Header.getDstAddr() + " : "
                            + ipV4Header.getProtocol() + " length: "
                            + packet.length()
                    );
                }
                else if(packet.contains(IpV6Packet.class)){
                    IpV6Packet.IpV6Header ipV6Header = packet.get(IpV6Packet.class).getHeader();
                    System.out.println(handle.getTimestamp() + " Type " + ethernetHeader.getType() + " "
                            + ipV6Header.getSrcAddr() + " > "
                            + ipV6Header.getDstAddr() + " : "
                            + ipV6Header.getProtocol() + " length: "
                            + packet.length()
                    );
                }
                else if(packet.contains(ArpPacket.class)){
                    ArpPacket.ArpHeader arpHeader = packet.get(ArpPacket.class).getHeader();
                    System.out.println(handle.getTimestamp() + " Type " + ethernetHeader.getType() + " "
                            + arpHeader.getSrcHardwareAddr() + " > "
                            + arpHeader.getDstHardwareAddr() + " : "
                            + arpHeader.getOperation() + " length: "
                            + packet.length()
                    );
                }
            }

            if(paketFull){
                System.out.println(packet);
            }



            if (write && dumper != null && (output || paketFull) ) {
                try {
                    dumper.dump(packet, handle.getTimestamp());
                } catch (NotOpenException e) {
                    logger.logWarning("Dumper status " + dumper);
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
                    logger.logInfo("Instructed to break loop.");
                } catch (IOException e) {
                    logger.logWarning(e.toString());
                    e.printStackTrace();
                }
                try {
                    handle.breakLoop();
                    logger.logInfo("Broke loop.");
                } catch (NotOpenException e) {
                    logger.logWarning("Trying to close not opened handle");
                    logger.logWarning(e.toString());
                    logger.logWarning(handle.toString());
                }
            });
            t.start();
        }

        ExecutorService pool = Executors.newCachedThreadPool();
        // Tell the handle to loop using the listener or dumper
        try {
            int maxPackets = (count == null) ? -1 : Integer.parseInt(count);
            if ((!output && !paketFull && write && dumper != null)) {
                logger.logInfo("Starting dumper loop.");
                handle.loop(maxPackets, dumper);
            } else {
                logger.logInfo("Starting listener loop.");
                handle.loop(maxPackets, listener, pool);
            }

        } catch (InterruptedException e) {
            logger.logInfo("Packet capturing finished.");
            System.out.println("Packet capturing finished");
        }

        // Cleanup when complete
        if (write && dumper != null){
            pool.awaitTermination(10, TimeUnit.SECONDS);
            dumper.close();
            logger.logInfo("Dumper closed.");
        }
        handle.close();
        logger.logInfo("Handle closed.");

        return 0;
    }

    public static void main(String[] args) {
        int rc = new CommandLine(new SnifferFinal()).execute(args);
        System.exit(rc);
    }

}
