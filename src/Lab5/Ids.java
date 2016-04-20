package Lab5;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.LinkedList;
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
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * 
 * @author Travis Wentz, Dustin Spivey, Trevor Gahl
 *
 */
public class Ids {

    private static int x = 1; //for packet handler loop
    private static String host = null;
    private static LinkedList<Policy> policies = new LinkedList<Policy>();
    private static String memDump = "";
    //private static final String ipRegex = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
    
    
     private static void readPolicyFile(String policyFileName) throws IOException{
        Pattern hostPattern1 = Pattern.compile("host=(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)");
        Pattern namePattern = Pattern.compile("name=(.)+$");
        Pattern typePattern = Pattern.compile("stateful|stateless");
        Pattern protoPattern = Pattern.compile("tcp|udp");
        Pattern hostPortPattern = Pattern.compile("host_port=[0-9a-zA-Z]+");
        Pattern attackerPortPattern = Pattern.compile("attacker_port=[0-9a-zA-Z]+");
        Pattern attackerPattern = Pattern.compile("attacker=any|attacker=(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)");
        Pattern fromHostPattern = Pattern.compile("from_host=(.)+$");
        Pattern toHostPattern = Pattern.compile("to_host=(.)+$");
        Matcher match;
    	String line = null;
        FileReader fileReader = new FileReader(policyFileName);
        BufferedReader bufferedReader = new BufferedReader(fileReader);
        int indexIterator = -1;

        while((line = bufferedReader.readLine()) != null) {
        	String helper = "";
            //get the host
            match = hostPattern1.matcher(line);
            if(match.find()){
            	for(int i = 5; i < match.group().length(); i++){
            		helper += match.group().charAt(i);
            	}
            	host = helper;
            }
            //get the name
            match = namePattern.matcher(line);
            if(match.find()){
            	
            	for(int i = 5; i < match.group().length(); i++){
            		helper += match.group().charAt(i);
            	}
            	indexIterator++;
            	Policy p = new Policy(helper);
            	policies.add(p);
            }
            //get the type
            match = typePattern.matcher(line);
            if(match.find()){
            	policies.get(indexIterator).setType(match.group());
            }
            //get the proto
            match = protoPattern.matcher(line);
            if(match.find()){
            	policies.get(indexIterator).setProto(match.group());
            }
            //get the host port
            match = hostPortPattern.matcher(line);
            if(match.find()){
            	
            	for(int i = 10; i < match.group().length(); i++){
            		helper += match.group().charAt(i);
            	}
            	policies.get(indexIterator).setHostPort(helper);
            }
            //get the attacker port
            match = attackerPortPattern.matcher(line);
            if(match.find()){
            	
            	for(int i = 14; i < match.group().length(); i++){
            		helper += match.group().charAt(i);
            	}
            	policies.get(indexIterator).setAttackerPort(helper);
            }
            //get the attacker ip
            match = attackerPattern.matcher(line);
            if(match.find()){
            	
            	for(int i = 9; i < match.group().length(); i++){
            		helper += match.group().charAt(i);
            	}
            	policies.get(indexIterator).setAttacker(helper);
            }
            //get from host
            match = fromHostPattern.matcher(line);
            if(match.find()){
            	
            	for(int i = 11; i < match.group().length() - 1; i++){
            		helper += match.group().charAt(i);
            	}
            	policies.get(indexIterator).setFromHost(helper);
            }
            //get to host
            match = toHostPattern.matcher(line);
            if(match.find()){
            	
            	for(int i = 9; i < match.group().length() - 1; i++){
            		helper += match.group().charAt(i);
            	}
            	policies.get(indexIterator).setToHost(helper);
            }
        }
        
        bufferedReader.close();
    }

    /*
	 * NOTE: some of the code in the following method was taken from the open-source
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
            final Udp udp = new Udp();
            final Payload payload = new Payload();
            
//            String test = "";
//            String regex = "[^((0-9a-zA-Z){2}' '.)] ";
            

            public void nextPacket(PcapPacket packet, String user) {
            	packet.getHeader(tcp);
                String currPayload = "";
                packet.getHeader(ip4);
                if (packet.hasHeader(Ip4.ID) && (FormatUtils.ip(ip4.destination()).equals(host)) && packet.hasHeader(Payload.ID)) {
                    
                    
                    if(packet.hasHeader(payload)){                    
                      currPayload = payload.toHexdump();
                      byte[] byteArray = payload.getByteArray(0, payload.getLength());
                      try{
                          currPayload = new String(byteArray, "UTF-8");
                          memDump += currPayload;
                      }catch(UnsupportedEncodingException e){
                          System.out.println("Failed");
                          e.printStackTrace();
                      }
                    }
                    
                    for(int i = 0; i < policies.size(); i++){
//                    	Pattern pattern = Pattern.compile(policies.get(i).getToHost().get(0));
//                        Matcher match;
//                        match = pattern.matcher(currPayload);
//                        if(match.find()) {
                        	//policies.get(i).printPolicy();
//                    	String foobar = memDump;
//                		if(policies.get(i).getType().equals("stateless")){
//                			foobar = currPayload;
//                		}
            			if(checkMsg(policies.get(i).getToHost(),policies.get(i).getFromHost(),currPayload)){
                        	if(policies.get(i).getAttacker().equals("any") || policies.get(i).getAttacker().equals(FormatUtils.ip(ip4.source()))){
                        		int source = 0;
                        		int destination = 0;
                        		if(packet.hasHeader(tcp)){
                        			source = tcp.source();
                        			destination = tcp.destination();
                        		}
                        		else if(packet.hasHeader(udp)){
                        			source = udp.source();
                        			destination = udp.destination();
                        		}
                        		if(policies.get(i).getAttackerPort().equals("any") || (Integer.parseInt(policies.get(i).getAttackerPort())) == source){
                        			if(policies.get(i).getHostPort().equals("any") || (Integer.parseInt(policies.get(i).getHostPort())) == destination){
	                        			System.out.println("A match was found for '" + policies.get(i).getName() +"'");
		                                String currSource = FormatUtils.ip(ip4.source());
		                                System.out.println("The attacker IP is : " + currSource + "\n");
                        			}
                        		}
                        	}
            			}
                    }
                }
            }
        };
        
        pcap.loop(-1, handler, "hi"); //the "-1" value makes it run infinite times (to the end of the file)

        //TODO regexs to match policies
        pcap.close();
    }
    
    private static boolean checkMsg(LinkedList<String> toHost, LinkedList<String> fromHost, String payload){
    	
    	for(int i = 0; i < toHost.size(); i++){
    		Pattern pattern = Pattern.compile(toHost.get(i));
            Matcher match;
            match = pattern.matcher(payload);
            if(match.find()) {
            	//System.out.println(match.group());
            	return true;
            }
    	}
    	for(int i = 0; i < toHost.size(); i++){
    		Pattern pattern = Pattern.compile(toHost.get(i));
            Matcher match;
            match = pattern.matcher(payload);
            if(match.find()) {
            	//System.out.println(match.group());
            	return true;
            }
    	}
    	return false;
    }

    public static void main(String[] args) throws IOException {
		String traceName = "trace1.pcap";
		String policyName = "policies.txt";
 
		if(1<args.length){
			traceName = args[1];
			policyName = args[0];
		}
    	readPolicyFile(policyName);
        readPcapFile(traceName);
    }

}
