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
public class Jail {
    
    private String originalName;
    private String name, failRegex, ignoreRegex, configString;
    
    public Jail(){
        name = failRegex = ignoreRegex = configString = "";
    }
    public Jail(String name, String failRegex, String ignoreRegex, String configString){
        this.name = name;
        this.failRegex = failRegex;
        this.ignoreRegex = ignoreRegex;
        this.configString = configString;
    }
    
    @Override 
    public boolean equals(Object obj){
        try{
            Jail fr = (Jail)obj;
            return fr.getName().equals(this.name);
        } catch(ClassCastException err){
            return false;
        }
    }
    public String getName(){return name;}
    public String getFailRegex(){return failRegex;}
    public String getIgnoreRegex(){return ignoreRegex;}
    public String getConfigString(){return configString;}
    /**
     * Set the original name of this filter. The original name should be non-empty
     * only when this filter is saved to either filter.d/{@code name}(.local|.conf).
     */
    public void setOriginalName(){
        originalName = name;
    }
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
