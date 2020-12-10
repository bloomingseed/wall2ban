/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.firewall;

import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import wall2ban.BashInterpreter;

/**
 * Ultimate data access class for iptables application.
 * @see #IPContext()
 * @author xceeded
 */
public class IPContext {
    private ChainStore chainStore;
    private IPRuleStore ruleStore;
    private BashInterpreter bashi;
    /**
     * Create the chains and rules from the underlaying iptables.
     * @throws IOException If communication with terminal failed.
     * @throws Exception If parsing iptables failed.
     * @see ChainStore
     * @see IPRuleStore
     */
    public IPContext() throws IOException, Exception {
        this.chainStore = new ChainStore();
        this.ruleStore = new IPRuleStore(this.chainStore);
        bashi = new BashInterpreter();
    }
    /**
     * 
     * @return ChainStore for this iptables.
     */
    public ChainStore getChainStore(){return this.chainStore;}
    /**
     * 
     * @return IPRuleStore for this iptables.
     */
    public IPRuleStore getRuleStore(){return this.ruleStore;}
    
    
    /**
     * Deletes all chains created by user, that is chains except 
     * 3 default ones: INPUT, OUTPUT and FORWARD.
     */
    public void resetIPTable() throws Exception{
        String command = "iptables -F"; // creates flush command
        if(bashi.executeRoot(command)!=0)
            throw new Exception("Failed to flush rules");
        List<Chain> chains = chainStore.readAll();
        for(int i = 3; i<chains.size(); ++i){
            Chain c = chains.get(i);    // gets current chain
            command = "iptables -X "+c.getName();   // creates delete chain command
            if(bashi.executeRoot(command)!=0)
                throw new Exception("Failed to delete chain "+c.getName());
            
        }
        chainStore = new ChainStore();  // reloads chain store
        ruleStore=  new IPRuleStore(chainStore); // reloads rule store
    
    }
    
    public static void main(String[] args){
        
        try {
            IPContext ctx = new IPContext();
            IPRule r1 = new IPRule();
            r1.setOwner(ctx.getChainStore().readByKey("INPUT"));
            ctx.getRuleStore().create(r1);
            
            System.out.println("Created new rule: "+r1.toString());
            
            
        } catch (Exception ex) {
            Logger.getLogger(IPContext.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
}
