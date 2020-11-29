/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.fail2ban;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import wall2ban.Utilities.Utils;

/**
 * A Bean model representing a fail2ban filter.
 * @author xceeded
 */
public class Jail extends HashMap<String,String>{
    /**
     * Name of the config file defining this jail. If the jail doesn't exist 
     * in physical memory then its value is {@code null}.
     */
    private String originalName;
    private String name;

    
    /**
     * The original configuration string of this jail for fail2ban-client.
     */
    private String configString;
    
    
    public Jail(){
        super();
    }
    public Jail(String name, String configString) throws Exception{
        this();
        setName(name);
        setConfigString(configString);
    }
    
    
    @Override 
    public boolean equals(Object obj){
        try{
            Jail jail = (Jail)obj;
            String name = jail.getName();
            return name!=null && name.equals(this.name);
        } catch(ClassCastException err){
            return false;
        }
    }
    
    
    public String getOriginalName(){return originalName;}    
    public String getName(){return this.name;}
    public String getConfigString(){return configString;}
    
    /**
     * Set the original name of this jail.The original name is
     * set equals to the name of this jail.
     */
    public void setOriginalName(){
        originalName = name;
    }
    
    public void setName(String value) throws Exception {
        if(value==null || value.isBlank())
            throw new Exception();
        this.name = value;
    }
    
    public void setConfigString(String value) throws Exception{
        if(value==null || value.isBlank())
            throw new Exception();
        this.configString = value;
    }
    /**
     * Factory method to create a filter using a valid config string.
     * @param configString A valid config string usually found in a filter config file.
     * @return The fully initialized filter.
     */
    public static Jail parseJail(String configString) throws Exception{
        Jail jail = new Jail();
        jail.setConfigString(configString);
        String[] lines = configString.split("\n");  // splits by line
        int N = lines.length;   // gets number of lines
        String sectionFormat = "(^\\s*\\[([\\w-]+)\\]\\s*$)";
        String propertyFormat = "(^\\s*([\\w-_]+)\\s*=([^\\n]*)$)";
        
        Pattern sectionPattern = Pattern.compile(sectionFormat);    // creates a pattern for sections
        Pattern propertyPattern = Pattern.compile(propertyFormat);    // creates a pattern for section properties
        
        Matcher m = sectionPattern.matcher(lines[0]);   // matches the section pattern against this line
        if(!m.matches())
            throw new Exception("Invalid config string. First line must contain jail name");
        String jailName = m.group(2);
        jail.setName(jailName);
        
        for(int i = 1; i<N;){
            m = propertyPattern.matcher(lines[i]);  // matches the property pattern against this line
            if(m.matches()){
                String key = m.group(2);    // gets the property key name
                StringBuilder value = new StringBuilder();// creates builder for the value
                value.append(m.group(3)).append("\n");    // appends key's value of this line

                // checks if this property's value expands to multi-line
                i=i+1;  // advances next line
                while(i<N && !Pattern.matches(propertyFormat,lines[i]) &&  // checks if the line isn't another property line
                        !Pattern.matches(sectionFormat, lines[i])){ // checks if the line isn't another section line
                    value.append(lines[i]).append("\n");  // appends this line to this property value
                    i=i+1;  //advances next line
                }
//                        i=i-1;  // steps back 1 line: next line: new property|new section

            jail.put(key,value.toString());  // add this key:value to the property map of this section
            }
            else 
                ++i;
        }
        return jail;
    }
    
    
    
    /**
     * Creates a filter from a config file. This factory method also
     * sets the created filter name to file name.
     * @param configFilePath
     * @return
     * @throws IOException 
     */
    public static Jail parseJail(Path configFilePath) throws IOException, Exception{
        String configStr = Files.readString(configFilePath);    // read file content
        
        Jail jail = Jail.parseJail(configStr); // parses a new filter
        jail.setOriginalName();  // sets filter name to where the config file is saved
        
        return jail;
    }
    
    public String toConfigString(){
        StringBuilder sbuilder=  new StringBuilder();   // creates builder 
        sbuilder.append(String.format("[%s]\n",this.name)); // adds jail name to builder
        for(Object property : this.keySet()){   // loops through each property in this jail
            // adds property and value pair to builder
            sbuilder.append(String.format("\t%s = %s\n",(String)property,(String)this.get(property)));

        }
        return sbuilder.toString(); // returns builder's content
    }
    
    /**
     * Overrides this jails configs with known local configs {@code filter} by:
     * <ol>
     * <li>Old colfig = new config is valuable ? new config : old config</li>
     * <li>Updates config string of this filter it self with {@link #updateConfigString()}.</li>
     * </ol>
     * @param jail Newer jail to override this jail.
     */
    public void override(Jail jail) throws Exception{
        setName(jail.getName());
        for(Object property : jail.keySet())
            if(this.keySet().contains(property))
                this.replace((String)property, (String)jail.get(property)); // sets new value for the property
            else
                this.put((String)property, (String)jail.get(property)); // sets new property value
    }
    
    public static void main(String[] args) throws IOException, Exception{
        
        test1();
        System.out.println("Test completed");
    }
    
    public static void test1() throws IOException, Exception{
        
        Path filePath = Paths.get(Utils.getWorkingFoler(),"/confsamples/jail/sshd.conf");
        Path file2 = Paths.get(Utils.getWorkingFoler(),"/confsamples/jail/sshd.local");
        
        String fContent = Files.readString(filePath);
//        String content2 = Files.readString(file2);
        
        Jail jail = Jail.parseJail(fContent);
        Jail jailLocal = Jail.parseJail(file2);
        System.out.println(jail.toConfigString());
        jail.override(jailLocal);
        System.out.println(jail.toConfigString());
    }   
    
    
    public static void test2() throws IOException{
        Path filePath = Paths.get(Utils.getWorkingFoler(),"/confsamples/filter/icmp-ping.conf");
        Filter ftr = Filter.parseFilter(filePath);
    }
    
}
