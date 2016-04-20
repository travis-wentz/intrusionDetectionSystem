/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Lab5;

import java.util.LinkedList;

/**
 *
 * @author Dustin
 */
public class Policy {

    private String name;
    private String type;
    private String host_port;
    private String attacker_port;
    private String attacker;
    private LinkedList<String> from_host = new LinkedList<>();
    private LinkedList<String> to_host = new LinkedList<>();
    private String proto;

    /*
     *
     *
     * @param name Name of policy
     *
     *
     */
    public Policy(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name; 
    }

    public String getType() {
        return this.type;
    }

    public String getProto() {
        return this.proto;
    }

    public String getAttacker() {
        return this.attacker;
    }

    public LinkedList<String> getFromHost() {
        return this.from_host;
    }

    public LinkedList<String> getToHost() {
        return this.to_host;
    }

    public String getHostPort() {
        return this.host_port;
    }

    public String getAttackerPort() {
        return this.attacker_port;
    }

    public void setFromHost(String from_host) {
        this.from_host.add(from_host);
    }

    public void setToHost(String to_host) {
        this.to_host.add(to_host);
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setProto(String proto) {
        this.proto = proto;
    }

    public void setAttacker(String attacker) {
        this.attacker = attacker;
    }

    public void setHostPort(String host_port) {
        this.host_port = host_port;
    }

    public void setAttackerPort(String attacker_port) {
        this.attacker_port = attacker_port;
    }
    public void printPolicy(){
        System.out.println("Policy name \t\t: "+getName());
        System.out.println("Policy type \t\t: "+getType());
        System.out.println("Policy host_port \t: "+getHostPort());
        System.out.println("Policy attacker_port \t: "+getAttackerPort());
        System.out.println("Policy attacker \t: "+getAttacker());
        for(int i=0;i<this.to_host.size(); i++){
            System.out.println("Policy to host \t\t: "+to_host.get(i));
        }
        for(int i=0;i<this.from_host.size(); i++){
            System.out.println("Policy from host \t: "+from_host.get(i));
        }
        System.out.println("Policy proto \t\t: "+getProto());
    }
}
