/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.firewall;

import java.util.ArrayList;
import java.util.regex.Pattern;

/**
 * A Bean representing an {@code iptables} rule in its chain.
 * @author xceeded
 */
public class IPRule {
    /**
     * The rule's target,aka. jump, which decides how the rule should be handled. 
     * E.g: DROP, ACCEPT, RETURN or other chain. For simplicity, it is of type {@code String}.
     */
    private String target;
    private String sourceIp, destIp, protocol;
    private int sourcePort, destPort;
    /**
     * The {@code chain} this rule belongs to. E.g: INPUT, OUTPUT, FORWARD or a custom chain. The default value is {@code null}.
     */
    private Chain owner;
    
    /**
     * Create a rule not belonging to a chain with no target and other specs being {@code any}, 
     */
    public IPRule(){   
        target = "DROP";    // set default target
        sourceIp = destIp = "";  // set default source and dest. ips
        protocol = "tcp";   // set default protocol 
    }
    public IPRule(String sourceIp, String destIp, String target, String protocol, int sourcePort, int destPort, Chain chain) throws Exception {
        setSourceIp(sourceIp);
        setDestinationIp(destIp);
        setTarget(target);
        setProtocol(protocol);
        setSourcePort(sourcePort);
        setDestinationPort(destPort);
        setOwner(chain);
    }
    
    @Override
    public boolean equals(Object e){
        IPRule rule = null;
        try{
            rule = (IPRule) e;
        } catch(Exception err){
            return false;
        }
        return (rule.getSourceIp().equals(this.sourceIp) &&
                rule.getSourcePort() == this.sourcePort &&
                rule.getDestinationIp().equals(this.destIp)&&
                rule.getDestinationPort() == this.destPort && 
                rule.getTarget().equals(this.target) && 
                rule.getProtocol().equals(this.protocol)&&
                rule.getOwner() == this.owner);
    }
    /**
     * Check if {@code ip} represents an IPv4 address.
     * @param ip
     * @return
     * @throws Exception 
     */
    private static boolean isIpv4Address(String ip) {
//        String[] byteStrings = ip.split("\\.");
//        if(byteStrings.length!=4)
//            return false;
//        try{
//            for(int i = 0; i<4; ++i)
//                if(Integer.parseInt(byteStrings[i])-255>0)  // if any octet has value greater than 255
//                    return false;
//        } catch(NumberFormatException err){
//            return false;
//        }
//        return true;
        return Pattern.matches("(^(\\d{1,3})(\\.\\d{1,3}){3}(/\\d{1,3})?$)",ip);
    }
    
    
    public String getSourceIp(){return sourceIp;}
    public String getDestinationIp(){return destIp;}
    public String getTarget(){return target;}
    public String getProtocol(){return protocol;}
    public int getSourcePort(){return sourcePort;}
    public int getDestinationPort(){return destPort;}
    public Chain getOwner(){return owner;}
    
    final public void setSourceIp(String sourceIp) throws Exception {
        
        if(!sourceIp.equals("any") && !isIpv4Address(sourceIp))
            throw new Exception("Invalid IP address");
        this.sourceIp= sourceIp;
    }
    final public void setDestinationIp(String destIp) throws Exception {
        if(!destIp.equals("any") && !isIpv4Address(destIp))
            throw new Exception("Invalid IP address");
        this.destIp=destIp;
    }
    final public void setTarget(String newTarget) throws Exception{
        if(newTarget==null || newTarget.isBlank())
            throw new Exception("Invalid target");
        target=newTarget;
    }
    final public void setProtocol(String newProtocol) throws Exception {
        if(newProtocol==null || newProtocol.isBlank())
            throw new Exception("Invalid protocol");
        protocol=newProtocol;
    }
    final public void setSourcePort(int sourcePort) throws Exception {
        if(sourcePort<0)
            throw new Exception("Invalid port number");
        this.sourcePort = sourcePort;
    }
    final public void setDestinationPort(int destPort) throws Exception {
        if(destPort<0)
            throw new Exception("Invalid port number");
        this.destPort = destPort;
    }
    /**
     * Method to bind this rule to a chain, or to unbind this rule from a chain (delete it) 
     * by also manipulating the {@code chain}'s rules list.
     * @param chain
     */
    final public void setOwner(Chain chain) {
        this.owner = chain;
        if(chain!=null){
            // add this rule to owner's rule list
            chain.getRules().add(this);
        }
        else{
            // remove this rule from owner's rule list
            chain.getRules().remove(this);
        }
    }
    
    @Override
    public String toString(){
        StringBuilder sb = new StringBuilder();
        // defines order for properties
        sb.append("-p ").append(protocol).
           append(sourceIp.isBlank()?"":" -s "+sourceIp).
           append(" --sport").append(" ").append(sourcePort).
           append(destIp.isBlank()?"":" -s "+destIp).
           append(" --dport").append(" ").append(destPort).
           append(" -j").append(" ").append(target);
        return sb.toString();
    }
    
    
    public static void main(String[] args) throws Exception{
//        test1();
        test3();
    }
    public static void test2() throws Exception {
        IPRule r1 = new IPRule(), r2 = new IPRule();
        System.out.println(r1==r2);
        System.out.println(r1.equals(r2));
        r1.setDestinationIp("192.168.1.1");
        r2.setDestinationIp("192.168.1.1");
        System.out.println(r1==r2);
        ArrayList<IPRule> rules = new ArrayList<IPRule>();
        rules.add(r1);
        System.out.println("Is r2 is inside list? "+rules.contains(r2));
        System.out.println("Removed r2 from list? "+rules.remove(r2));
    }
    
    public static void test3() throws Exception{
        String ip1 = "173.239.8.164/32",
                ip2 = "173.239.8.164";
        IPRule r1 = new IPRule();
        r1.setSourceIp(ip1);
        r1.setSourceIp(ip2);
        System.out.println(r1.toString());
        
    }
    
    
    
    
}
