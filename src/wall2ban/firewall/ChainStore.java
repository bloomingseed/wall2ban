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
 *
 * @author xceeded
 */
public class ChainStore implements IStore<Chain,String>{

    private ArrayList<Chain> chains;    // in-memory chains collection
    private BashInterpreter bashi;      // to communicate with terminal through shell cmd
    
    public ChainStore() throws Exception{
        bashi = new BashInterpreter();
       initializeChainsList();
       readAllFromTerminal();
    }
    
    /**
     * Create empty chains list then insert 3 default chains: INPUT, OUTPUT and FORWARD chains.
     */
    private void initializeChainsList(){
        chains = new ArrayList<Chain>();
        // add default chains
        chains.add(new Chain("INPUT"));
        chains.add(new Chain("OUTPUT"));
        chains.add(new Chain("FORWARD"));
    }
    
    /**
     * Contact iptables through terminal to initialize chains list
     */
    private void readAllFromTerminal() throws Exception{
        bashi.executeRoot("iptables -S");   
        String iptables = bashi.getResponse();// retrieve iptables save config
        Pattern p = Pattern.compile("(^-N ([\\w-]+)+$)");   // regex for create new chain command
        for(String line : iptables.split("\n")){    // for each line in result
            Matcher m = p.matcher(line);    // match pattern
            if(m.matches()){    // if pattern matches (create new chain command)
                String chainName = m.group(2);  // retrieve chain name from matcher
                this.chains.add(new Chain(chainName));  // add new chain with such name to list
            }
            
        }   
    }    
    
    @Override
    public List<Chain> readAll() {
        return this.chains;
    }

    @Override
    public Chain readByKey(String key) {
        for(Chain chain : chains)
            if(chain.getName().equals(key))
                return chain;
        return null;
    }

    @Override
    public void create(Chain entity) throws Exception {
        
        String createChainCommand = String.format("iptables -N %s",entity.getName());
        int code = bashi.executeRoot(createChainCommand);
        if(code!=0)
            throw new Exception("Failed to create new chain "+entity.getName());
        this.chains.add(entity);    // add new chain to RAM's chains collection
    }

    /**
     * This method is not supported. Use {@link #rename(Chain,String)} instead.
     * @param entity
     * @throws UnsupportedOperationException Always
     * @deprecated
     * @see #rename(Chain,String)
     */
    @Override
    @Deprecated
    public void update(Chain entity) throws UnsupportedOperationException{
        throw new UnsupportedOperationException("Can only change chain name with rename(Chain,String)."); //To change body of generated methods, choose Tools | Templates.
    }
    
    /**
     * Replaces this chain's name with the specified name
     * @param chain
     * @param newName 
     * @throw Exception If communication with terminal fails
     */
    public void rename(Chain chain, String newName) throws Exception{
        
        String command = String.format("iptables --rename-chain %s %s",chain.getName(),newName);
        int code = bashi.executeRoot(command);
        if(code!=0)    // check if the response is a failed one
            throw new Exception("Failed to rename chain "+chain.getName()+" to "+newName); // throw
        chain.setName(newName);
    }

    @Override
    public void delete(Chain entity) throws Exception {
        String command = null;
        // delete all rules in the chain
        for(int i = entity.getRules().size(); i>0; --i){
            command = String.format("iptables -D %s %d",entity.getName(),i);
            int exitCode = bashi.executeRoot(command);   // delete rule number. i
            if(exitCode!=0)
                throw new Exception("Failed to delete "+entity.getName()+"'s rule number. "+i);
        }
        command = String.format("iptables -X %s",entity.getName());
        int code = bashi.executeRoot(command); // terminal response for deleting chain command
        if(code!=0)    // check if the response is a failed one
            throw new Exception("Failed to delete chain "+entity.getName()); // throw
        this.chains.remove(entity); // remove this chain from collection
    }
    /**
     * Deletes all chains created by user, that is chains except 
     * 3 default ones: INPUT, OUTPUT and FORWARD.
     */
    public void resetIPTable() throws Exception{

        for(int i = 3; i<this.chains.size();++i){
            Chain chain = this.chains.get(i);   // refers to the chain to delete
            delete(chain);
        }
    
    }
    
    public static void main(String[] args){
        
        try{
            
            ChainStore store = new ChainStore();
            IPRuleStore ruleStore = new IPRuleStore(store);
            
            store.delete(store.readByKey("stub-chain"));
            
            System.out.println("Deletion succeeded");
            
        }catch(Exception err){
            err.printStackTrace();
        }
        
    }
    
}
