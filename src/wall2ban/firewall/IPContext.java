/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.firewall;

import java.io.IOException;
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
    
    public static void main(String[] args){
        
        try {
            IPContext ctx = new IPContext();
            IPRule r1 = new IPRule();
            r1.setOwner(ctx.getChainStore().readByKey("INPUT"));
            ctx.getRuleStore().create(r1);
            
            System.out.println("Created new rule: "+r1.toString());
            
            ctx.getChainStore().resetIPTable();
            
            
        } catch (Exception ex) {
            Logger.getLogger(IPContext.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
}
