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
 * @see Chain()
 * @see Chain(String)
 * @see Chain(Chain)
 * @author xceeded
 */
public class Chain {
    private String name;
    private List<IPRule> rules;
    /**
     * Create chain with empty rules list and name being null.
     * @see Chain(String)
     */
    public Chain(){
        rules = new ArrayList<IPRule>();
    }
    /**
     * Create chain with specified name and empty rule list
     * @param name
     * @throws IllegalArgumentException If chain name is invalid.
     * @see #Chain()
     */
    public Chain(String name) throws IllegalArgumentException{
        this();
        setName(name);
    }
    /**
     * Copy constructor copies the name and all rules elements
     * in the specified chain. If specified chain is null then default
     * constructor is called.
     * @param chain Chain being copied
     */
    public Chain(Chain chain){
        this(); // calls default constructor
        if(chain!=null){
            this.name = chain.name;
            // Shallow copying immutables works as if hard copying
            this.rules.addAll(chain.rules); // shallow copies rules from chain
        }
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
