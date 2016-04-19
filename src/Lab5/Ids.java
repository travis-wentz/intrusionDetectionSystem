package Lab5;
//Travis is here

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.format.XmlFormatter;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;

public class Ids {

    private static int x = 1; //for testing packet handler loop

    /*
	 * NOTE: most of the code in the following method was taken from the open-source
	 * 		tutorials by jnetpcap
	 * 		http://jnetpcap.com/?q=userguide
     */
    private static void readPcapFile(String pcapFileName) {
        StringBuilder err = new StringBuilder();
        Pcap pcap = Pcap.openOffline(pcapFileName, err);

        if (pcap == null) {
            System.out.println("There was an error reading your trace file. "
                    + "Please make sure it is in the project folder and is spelled correctly.");
            return;
        }

        PcapPacketHandler<String> handler = new PcapPacketHandler<String>() {
            final Ip4 ip4 = new Ip4();
            final Tcp tcp = new Tcp();
            final Payload payload = new Payload();
            Pattern pattern = Pattern.compile("Now I own your computer");
            Matcher match;
            String test = "";
            String regex = "[^((0-9a-zA-Z){2}' '.)] ";
            

            public void nextPacket(PcapPacket packet, String user) {
                String currPayload = "";
                if (packet.hasHeader(Ip4.ID)) {
                    packet.getHeader(ip4);
                    if(packet.hasHeader(payload)){                    
                        currPayload = payload.toHexdump();
                        byte[] byteArray = payload.getByteArray(0, payload.getLength());
                        try{
                            currPayload = new String(byteArray, "UTF-8");
                        }catch(UnsupportedEncodingException e){
                            System.out.println("Failed");
                            e.printStackTrace();
                        }
                        match = pattern.matcher(currPayload);
                  //      System.out.println("\n The payload info is :\n " + currPayload + "\n");
                        if(match.find()) {
                          System.out.println("A match was found for '"+match.group()+"'");

                        }
                    }
                    String currSource = FormatUtils.ip(ip4.source());
                    System.out.println("The source IP is : " + currSource + "\n");

                }
//				System.out.println(x + " " + "size of packet is=" + packet.size());
//				x++;

                //print out all the packet info
//                XmlFormatter out = new XmlFormatter(System.out);
//                try {
//
//                    out.format(packet);
//                } catch (IOException e) {
//                    // TODO Auto-generated catch block
//                    e.printStackTrace();
//                }
            }
        };
        pcap.loop(-1, handler, "hi"); //the "-1" value makes it run infinite times (to the end of the file)

        //TODO regexs to match policies
        pcap.close();
    }

    //this should take in a packet as an argument
    private static void regexMatching() {

    }

    public static void main(String[] args) {
//		Scanner in = new Scanner(System.in);
//		String input = null;
//		File policyFile;
//		File traceFile;
//		
//		System.out.println("Please enter the name of the policy file:");
//		input = in.nextLine();
//		policyFile = new File(input);
//		if(!policyFile.exists()){
//			input += ".txt";
//			policyFile = new File(input);
//			if(!policyFile.exists()){
//				System.out.println("Policies file not found. Please make sure it is in the project folder for lab 5.");
//				in.close();
//				return;
//			}
//		}
//		
//		System.out.println("Please enter the name of the trace file:");
//		input = in.nextLine();
//		in.close();
//		traceFile = new File(input);
//		if(!traceFile.exists()){
//			System.out.println("Trace file not found. Please make sure it is in the project folder for lab 5.");
//		}else{
//			readPcapFile(input);
//		}

        readPcapFile("trace1.pcap");
    }

}
