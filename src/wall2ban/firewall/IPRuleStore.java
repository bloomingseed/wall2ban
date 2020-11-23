/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.firewall;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import wall2ban.BashInterpreter;
import wall2ban.IStore;

/**
 * DAO class for IPRule objects. It contains the collection to retrieve ip rule and
 * methods to CRUD iptables.
 * @author xceeded
 * @param <IPRule> Type of entity to manipulate
 * @param <String> Type of id field
 * 
 */
public class IPRuleStore implements IStore<IPRule,Integer>{
    /**
     * RAM collection of ip rules
     */
    private List<IPRule> ruleList;
    /**
     * Handle iptables CRUD through bash terminal shell commands and string processing.
     */
    private BashInterpreter bashi;
    /**
     * Reference to DAO object for {@link Chain Chain} objects. It is used to handle setting and removing rule's {@link IPRule#owner owner}.
     */
    private ChainStore chainStore; 
    /**
     * DEVELOPMENT: store the root password to call privileged commands
     */
    private static String ROOT_PASS="mynewbnscharactersnameislukie";

    /**
     * Create blank {@link #ruleList}, initialize internal {@link BashInterpreter terminal interpreter},
     * set reference to specified chain DAO, fetch all rules from iptables.
     * @param chainStore
     * @throws IOException
     * @throws Exception If set() method failed
     * 
     */
    public IPRuleStore(ChainStore chainStore) throws IOException, Exception{
        this.chainStore = chainStore;
        bashi = new BashInterpreter();
        readAllFromTerminal();  // initializes new rule list
    }
    /**
     * Call shell command to show ip rules then parse it to this ruleList. 
     * This method is called by {@link #readAll()}.
     * @throws IOException
     * @throws Exception 
     */
    private void readAllFromTerminal() throws IOException, Exception {
        // DEVELOPMENT: specify password; remove this in PRODUCTION
        bashi.setCommand("echo "+ROOT_PASS+" | sudo -S iptables -S");
        bashi.execute();    // execute command
        String iptables = bashi.getResponse();  // retrieves response
        
        ruleList = new ArrayList<IPRule>();        
        Pattern p = Pattern.compile("(^-A ([\\w-]+) (.*)$)");   // regex for append rule command
        for(String line : iptables.split("\n")){    // for each line in result
            Matcher m = p.matcher(line);    // match pattern
            if(m.matches()){    // if pattern matches (append rule command)
                IPRule rule= new IPRule();   // create empty rule
                String owner = m.group(2);  // get rule's chain
                String params = m.group(3);     // get rule configs
                rule.setOwner(this.chainStore.readByKey(owner));   // set rule's chain
                // specify known flags to initialize rule configs
                String[] knownFlags = new String[]{"-p","-s","-d","--sport","--dport","-j"};    
                for(String flag : knownFlags){  // for each flag
                    // try match the param with this `flag`
                    m=Pattern.compile(String.format("(^[^\\n]*(%s) ([\\w-/\\.]+)[^\\n]*$)",flag)).matcher(params);
                    if(m.matches()){    // if the `flag` exists in params
                        String key = m.group(2);    // retrieve matched flag
                        String value = m.group(3);  // get flag's value
                        // e.g. -p tcp
                        try{
                            switch(key){    // see which flag is matched
                            case "-p":  // rule has protocol spec
                                rule.setProtocol(value);    // set rule's protocol
                                break;
                            case "-s":  // rule has source ip spec
                                rule.setSourceIp(value);
                                break;
                            case "-d":  // rule has dest ip spec
                                rule.setDestinationIp(value);
                                break;
                            case "--sport": // rule has source port spec
                                rule.setSourcePort(Integer.parseInt(value));
                                break;
                            case "--dport": // rule has dest port spec
                                rule.setDestinationPort(Integer.parseInt(value));
                                break;
                            case "-j":  // rule has target spec
                                rule.setTarget(value);
                                break;
                        }
                        } catch(Exception err){ throw err;} // if set() failed then throw
                    }
                }
                this.ruleList.add(rule);    // add found rule
            }
        }
        
        
    }

    @Override
    public List<IPRule> readAll() {
        return this.ruleList;
    }

    @Override
    public IPRule readByKey(Integer key) {
        return this.ruleList.get(key);
    }

    @Override
    public void create(IPRule entity) throws Exception {
        
        if(entity.getOwner()==null) // checks if the rule has owner chain
            throw new Exception("Failed to create rule with no belonging chain: "+entity.toString());
        
        String ruleSpecs = entity.toString();   // retrieves the specifications of the rule
        String command = String.format("iptables -A %s %s",entity.getOwner().getName(),ruleSpecs);
        int code = bashi.executeRoot(command);
        if(code!=0)    // check if the response is a failed one
            throw new Exception("Failed to create rule "+ruleSpecs); // throw
        this.ruleList.add(entity);     
        
    }
    /** 
     * This method is not supported. Use {@link #updateIndex(int,IPRule)} instead.
     * @throws UnsupportedOperationException Always.
     * @deprecated 
     * @see #updateIndex(int,IPRule)
     */
    @Override
    @Deprecated
    public void update(IPRule entity) throws UnsupportedOperationException{
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
    /**
     * Updates the ip rule at the specified {@code ruleIndex} in the rule's chain.
     * @param ruleIndex
     * @param entity 
     */
    public void updateIndex(int ruleIndex, IPRule entity) throws Exception{
        String ruleSpecs = entity.toString();   // retrieves the specifications of the rule
        // specifies shell command to execute
        String command = String.format("iptables -R %s %d %s",entity.getOwner().getName(),ruleIndex,ruleSpecs);   
        
        if(bashi.executeRoot(command)!=0)
            throw new Exception("Failed to update rule #"+ruleIndex+" to "+ruleSpecs);
        this.ruleList.set(ruleIndex, entity);   // replaces the rule number. ruleIndex with entity
        
    }

    @Override
    public void delete(IPRule entity) throws Exception {
        int ruleIndex = this.ruleList.indexOf(entity);  // gets the index of entity in the rules list
        ruleIndex = ruleIndex+1;    // uses 1-indexing
        String ruleSpecs = entity.toString();   // gets the rule specifications
        if(ruleIndex <1)
            throw new Exception("Failed to delete. Rule does not exist: "+ruleSpecs);
        // specifies shell command to execute
        String command = String.format("iptables -D %s %d",entity.getOwner().getName(),ruleIndex);   
        
        if(bashi.executeRoot(command)!=0)
            throw new Exception("Failed to update rule #"+ruleIndex+" to "+ruleSpecs);
        this.ruleList.set(ruleIndex, entity);   // replaces the rule number. ruleIndex with entity
        
    }
    
    public static void main(String[] args){
        
        try{
            ChainStore cstore = new ChainStore();
            IPRuleStore store = new IPRuleStore(cstore);
            
            Chain fooChain = null;
            try{
                fooChain = new Chain("bloomingseed-stub");
                cstore.create(fooChain);
            } catch(Exception err){
                fooChain = cstore.readByKey("bloomingseed-stub");
            }
            IPRule rule = new IPRule();
            rule.setOwner(fooChain);
            
            store.create(rule);
            System.out.println();
            
            
        } catch(Exception err){
            err.printStackTrace();
        }
        
    }
    
}
