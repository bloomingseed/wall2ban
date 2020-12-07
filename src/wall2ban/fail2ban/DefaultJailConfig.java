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
import wall2ban.Utilities;

/**
 *
 * @author xceeded
 */
public class DefaultJailConfig extends HashMap<String,Map<String,String>>{
    
    private String configString;
    
    public DefaultJailConfig(){
        super();
    }
    
    public String getConfigString(){return configString;}
    public void setConfigString(String configString) {
        this.configString = configString;
    }
    public String toConfigString(){
        StringBuilder sbuilder=  new StringBuilder();   // creates builder 
        for(Object sectionKey : this.keySet()){
            Map<String,String> propMap = (Map<String,String>)this.get(sectionKey);
            sbuilder.append(String.format("[%s]\n",(String)sectionKey));
            for(Object property : propMap.keySet()){   // loops through each property in this jail
                // adds property and value pair to builder
                sbuilder.append(String.format("\t%s = %s\n",(String)property,(String)propMap.get(property)));

            }
        }
        return sbuilder.toString(); // returns builder's content
    }
    
    public static DefaultJailConfig parseDefaultJailConfig(String configString){
        DefaultJailConfig jailConfig = new DefaultJailConfig();
        jailConfig.setConfigString(configString);
        
        String[] lines = configString.split("\n");  // splits by line
        int N = lines.length;   // gets number of lines
        String sectionFormat = "(^\\s*\\[([^\\n]+)\\]\\s*$)";   // regex for line of section
        String propertyFormat = "(^([\\w-_]+)\\s*=([^\\n]*)$)"; // regex for line of property
        
        Pattern sectionPattern = Pattern.compile(sectionFormat);    // creates a pattern for sections
        Pattern propertyPattern = Pattern.compile(propertyFormat);    // creates a pattern for section properties
        
        for(int i = 0; i<N;){
            
            Matcher m = sectionPattern.matcher(lines[i]);   // matches the section pattern against this line
            if(m.matches()){    // checks if this line matches the section pattern
                String sectionName = m.group(2);    // gets the section name
                Map<String,String> propMap = new HashMap<String,String>();  // creates new property map for this section
                jailConfig.put(sectionName, propMap);    // creates new section
                
                i=i+1;  // advances next line
                while(i<N && !Pattern.matches(sectionFormat, lines[i])){   // checks if this line still matches a section format
                    m = propertyPattern.matcher(lines[i]);  // matches the property pattern against this line
                        if(m.matches()){
                        
                        String key = m.group(2);    // gets the property key name
                        StringBuilder value = new StringBuilder();// creates builder for the value
                        value.append(m.group(3));    // appends key's value of this line

                        // checks if this property's value expands to multi-line
                        i=i+1;  // advances next line
                        while(i<N && !Pattern.matches(propertyFormat,lines[i]) &&  // checks if the line isn't another property line
                                !Pattern.matches(sectionFormat, lines[i])){ // checks if the line isn't another section line
                            if(!lines[i].isBlank())
                                value.append("\n").append(lines[i]);  // appends this line to this property value
                            i=i+1;  //advances next line
                        }
//                        i=i-1;  // steps back 1 line: next line: new property|new section

                        propMap.put(key,value.toString());  // add this key:value to the property map of this section
                    }
                    else 
                        ++i;
                }
            }
            else 
                ++i;
        }
        return jailConfig;        
        
    }
    
    public void override(DefaultJailConfig jailConfig) throws Exception{
        for(Object sectionKey : jailConfig.keySet()){
            Map<String,String> section = (Map<String,String>)jailConfig.get(sectionKey);    // gets map associated with this key
            if(!this.keySet().contains(sectionKey)) // checks if this map contains the section yet
                this.put((String)sectionKey, section);  // adds the section to this map
            else{   
                Map<String,String> selfSection = (Map<String,String>)this.get(sectionKey);  // gets the map of this object for this section 
                for(Object property : section.keySet())
                    if(!selfSection.containsKey(property))  // checks if self section doesnt contain this property
                        selfSection.put((String)property,section.get(property));    // adds this property to self section
                    else
                        selfSection.replace((String)property,section.get(property));    // replaces the property's value in self section
            }
        }
    }
    
    
    public static void main(String[] args) throws IOException, Exception{
        
        test1();
        System.out.println("Test completed");
    }
    
    public static void test1() throws IOException, Exception{
        
        Path filePath = Paths.get(Utilities.Utils.getWorkingFoler(),"/confsamples/jail/jail.conf");
        String config = Files.readString(filePath);
        DefaultJailConfig jailConfig = DefaultJailConfig.parseDefaultJailConfig(config);
        
        filePath = Paths.get(Utilities.Utils.getWorkingFoler(),"/confsamples/jail/jail.local");
        config = Files.readString(filePath);
        DefaultJailConfig jailConfigLocal = DefaultJailConfig.parseDefaultJailConfig(config);
        
        jailConfig.override(jailConfigLocal);
    }
    
}
