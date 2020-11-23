/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.firewall;

import java.util.ArrayList;
import java.util.List;

/**
 * A Bean representing an ip chain with its rules list.
 * @author xceeded
 */
public class Chain {
    private String name;
    private List<IPRule> rules;
    /**
     * Create chain with empty rules list and unspecified name
     * @see Chain(String)
     */
    public Chain(){
        rules = new ArrayList<IPRule>();
    }
    /**
     * Create chain with specified name and empty rule list
     * @param name
     * @throws IllegalArgumentException If chain name  
     * @see #Chain()
     */
    public Chain(String name) throws IllegalArgumentException{
        this();
        setName(name);
    }
    
    @Override
    public boolean equals(Object obj){
        try{
            Chain chain = (Chain)obj;
            return (chain.name.equals(this.name));
        } catch(ClassCastException err){
            return false;
        }
    }
    public String getName(){return name;}
    public List<IPRule> getRules(){return rules;}
    /**
     * Set this chain's name.
     * @param name
     * @throws IllegalArgumentException  If {@code name} is null or empty.
     */
    public void setName(String name) throws IllegalArgumentException{
        if(name==null || name.isEmpty())
            throw new java.lang.IllegalArgumentException();
        this.name = name;
    }
    
    
}
