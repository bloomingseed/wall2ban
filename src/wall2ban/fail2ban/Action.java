/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.fail2ban;

/**
 * A Bean model representing a fail2ban filter.
 * @author xceeded
 */
public class Action {
    private String name, failRegex, ignoreRegex, configString;
    
    public Action(){
        name = failRegex = ignoreRegex = configString = "";
    }
    public Action(String name, String failRegex, String ignoreRegex, String configString){
        this.name = name;
        this.failRegex = failRegex;
        this.ignoreRegex = ignoreRegex;
        this.configString = configString;
    }
    
    @Override 
    public boolean equals(Object obj){
        try{
            Action fr = (Action)obj;
            return fr.getName().equals(this.name);
        } catch(ClassCastException err){
            return false;
        }
    }
    public String getName(){return name;}
    public String getFailRegex(){return failRegex;}
    public String getIgnoreRegex(){return ignoreRegex;}
    public String getConfigString(){return configString;}
    
    public void setName(String value){
        name = value!=null?value:"";
    }
    public void setFailRegex(String value){
        failRegex = value!=null?value:"";
    }
    public void setIgnoreRegex(String value){
        ignoreRegex = value!=null?value:"";
    }
    public void setConfigString(String value){
        configString = value!=null?value:"";
    }
}
