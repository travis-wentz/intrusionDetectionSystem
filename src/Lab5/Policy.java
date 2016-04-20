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

    private String host;
    private String name;
    private String type;
    private int host_port;
    private int attacker_port;
    private String attacker;
    private LinkedList<String> from_host;
    private LinkedList<String> to_host;
    private String proto;

    /**
     *
     * This class is for blah
     *
     * @param host IP address of host
     * @param name Name of policy
     * @param type Type of policy (stateful|stateless)
     * @param proto Protocol used TCP or UDP
     * @param host_port Port host is using
     * @param attacker_port Port attacker is using
     * @param attacker IP address of attacker
     * @param from_host String from host (from_host|to_host)=regexp\n
     * @param to_host String to host (from_host|to_host)=regexp\n
     */
    public Policy(String host,
            String name,
            String type,
            String proto,
            int host_port,
            int attacker_port,
            String attacker,
            String from_host,
            String to_host
    ) {

        this.host = host;
        this.name = name;
        this.type = type;
        this.proto = proto;
        this.host_port = host_port;
        this.attacker_port = attacker_port;
        this.attacker = attacker;
        this.from_host.add(from_host);
        this.to_host.add(to_host);
    }
        public Policy(String host,
            String name,
            String type,
            int host_port,
            int attacker_port,
            String attacker,
            String from_host,
            String to_host
    ) {

        this.host = host;
        this.name = name;
        this.type = type;
        this.host_port = host_port;
        this.attacker_port = attacker_port;
        this.attacker = attacker;
        this.from_host.add(from_host);
        this.to_host.add(to_host);
    }

    public String getHost() {
        return this.host;
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

    public int getHostPort() {
        return this.host_port;
    }

    public int getAttackerPort() {
        return this.attacker_port;
    }

    public void addFromHost(String from_host) {
        this.from_host.add(from_host);
    }

    public void addToHost(String to_host) {
        this.to_host.add(to_host);
    }
}
