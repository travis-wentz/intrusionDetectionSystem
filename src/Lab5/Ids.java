package Lab5;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class Ids {
	
	public Ids(){
		Scanner in = new Scanner(System.in);
		String input = null;
		File policyFile;
		File traceFile;
		
		System.out.println("Please enter the name of the policy file:");
		input = in.nextLine();
		policyFile = new File(input);
		if(!policyFile.exists()){
			input += ".txt";
			policyFile = new File(input);
			if(!policyFile.exists()){
				System.out.println("Policies file not found. Please make sure it is in the project folder for lab 5.");
				in.close();
				return;
			}
		}
		
		System.out.println("Please enter the name of the trace file:");
		input = in.nextLine();
		in.close();
		traceFile = new File(input);
		if(!traceFile.exists()){
			System.out.println("Trace file not found. Please make sure it is in the project folder for lab 5.");
		}else{
			readPcapFile(input);
		}
	}
	
	private void readPcapFile(String pcapFileName){
		Pcap pcap = Pcap.openOffline(pcapFileName, null);
		
		if(pcap == null){
			System.out.println("There was an error reading your trace file. "
					+ "Please make sure it is in the proper directory and spelled correctly.");
			return;
		}
		
		//TODO figure out how to read the packets
		
		//TODO regexs to match policies
	}
	
	//this should take in a packet as an argument
	private void regexMatching(){
		
	}

	public static void main(String[] args) {
		new Ids();
	}

}
