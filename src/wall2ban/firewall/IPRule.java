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
 * @see IPRule
 * @see IPRule(String,String,String,String,int,int,Chain)
 * @see IPRule(IPRule)
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
     * Create a rule not belonging to a chain with {@code DROP} target,
     * protocol of {@code tcp} and other specs implying any, 
     */
    public IPRule(){   
        target = "DROP";    // set default target
        sourceIp = destIp = "";  // set default source and dest. ips
        protocol = "tcp";   // set default protocol 
    }
    /**
     * Creates a full rule following the specified parameters.
     * @param sourceIp
     * @param destIp
     * @param target
     * @param protocol
     * @param sourcePort
     * @param destPort
     * @param chain
     * @throws Exception 
     */
    public IPRule(String sourceIp, String destIp, String target, String protocol, int sourcePort, int destPort, Chain chain) throws Exception {
        setSourceIp(sourceIp);
        setDestinationIp(destIp);
        setTarget(target);
        setProtocol(protocol);
        setSourcePort(sourcePort);
        setDestinationPort(destPort);
        setOwner(chain);
    }
    /** 
     * Copy constructor copies all members of specified rule.
     * If specified rule is null then default constructor is called.
     * @see #IPRule()
     * @param rule 
     */
    public IPRule(IPRule rule){
        this(); // calls default constructor to initializes members
        if(rule!=null){ // checks if specified rule is a valid rule
            // shallow copies all (immutable) members.
            this.destIp = rule.destIp;
            this.sourceIp = rule.sourceIp;
            this.destPort = rule.destPort;
            this.sourcePort = rule.sourcePort;
            this.target = rule.target;
            this.protocol = rule.protocol;
            this.owner = rule.owner;    // sets to same owner (not hard-copying owner)
        }
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
     * Check if {@code ip} represents an IPv4 address with optionally 
     * subnet mask.
     * @param ip
     * @return
     * @throws Exception 
     */
    private static boolean isIpv4Address(String ip) {
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
