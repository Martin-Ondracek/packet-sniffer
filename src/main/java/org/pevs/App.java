package org.pevs;

import java.io.IOException;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
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
        PcapNetworkInterface device = getNetworkDevice();
        System.out.println("You chose: " + device);

        // skuska gitu
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
        String filter = "tcp port 80";
        //handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        // Create a listener that defines what to do with the received packets
        PacketListener listener = new PacketListener() {
            //@Override
            public void gotPacket(Packet packet) {
                // Override the default gotPacket() function and process packet
                System.out.println(handle.getTimestamp());
                System.out.println(packet);
            }
        };

        // Tell the handle to loop using the listener we created
        try {
            int maxPackets = 10;
            handle.loop(maxPackets, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Cleanup when complete
        handle.close();
    }

}
