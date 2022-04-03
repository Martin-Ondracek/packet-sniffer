package org.pevs;

import java.util.Scanner;

public class BpfFilterBuilder {
    private String bpf;
    private final Scanner sc = new Scanner(System.in);

    public BpfFilterBuilder(){

    }

    public String setFilter(){

        bpf = setDstPort();
        return this.bpf;
    }

    private boolean isOver(){
        System.out.println("Add another filter? y/n");
        String option = sc.next();
        return option.charAt(0) == ('y');
    }

    private String setDstAddress(){
        System.out.println("Enter desired destination address: ");
        return "dst host " + sc.next();
    }

    private String setSrcAddress(){
        System.out.println("Enter desired source address: ");
        return "src host " + sc.next();
    }

    private String setSrcPort(){
        System.out.println("Enter desired source port number: ");
        int port = sc.nextInt();
        if(port > 65535 || 0 > port){
            System.out.println("Invalid port");
            return null;
        }
        return "dst port " + port;
    }

    private String setDstPort(){
        System.out.println("Enter desired destination port number: ");
        int port = sc.nextInt();
        if(port > 65535 || 0 > port){
            System.out.println("Invalid port");
            return null;
        }
        return "dst port " + port;
    }

    private String setProtocol(){
        while (true){
            System.out.println("Chose desired protocol: ");
            System.out.println("1.TCP" +
                    "\n2.UDP" +
                    "\n3.ARP" +
                    "\n4.ICMP");
            int option = sc.nextInt();

            if (option == 1) {
                return "tcp";
            } else if (option == 2){
                return "udp";
            }else if (option == 3){
                return "arp";
            }else if (option == 4){
                return "icmp";
            }else {
                System.out.println("Unknown option");
            }
        }

    }
}
