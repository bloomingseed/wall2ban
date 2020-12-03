/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.fail2ban;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import wall2ban.Utilities.Utils;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import wall2ban.StringUpdater;

/**
 * A Bean model representing a fail2ban filter.
 * @see Filter()
 * @see Filter(Filter)
 * @author xceeded
 */
public class Filter extends HashMap<String,Map<String,String>>{
    
    private String name;
    /**
     * Name of the file containing this filter's config, if its value is 
     * different from {@code null}. Excluding the extension: .conf, .local.
     */
    private String originalName;    
    private String configString;
    /**
     * Default initialization. Creates new action with
     * all members being {@code null} and with an empty "Definition" {@code section}.
     */
    public Filter(){
        super();
        Map<String,String> defSect = new HashMap<String,String>();  // creates empty section
        this.put("Definition", defSect);    // puts to filter config
    }
    /**
     * Copy constructor copies all members of specified filter and
     * all of its section & contents. If passed a null filter then 
     * members are initialized as default.
     * @param filter Filter being cloned.
     */
    public Filter(Filter filter){
        super();
        if(filter!=null){
            this.name = filter.name;
            this.originalName = filter.originalName;
            this.configString = filter.configString;
            
            this.clear();   // clears map
            for(Object key : filter.keySet()){  // loops through each section
                Map<String,String> propMap = (Map<String,String>) filter.get(key);  // gets section's property map
                // propMap is map of immutables so shallow cloning works as deep cloning
                Map<String,String> clone = new HashMap<String,String>(propMap); // shallow copies propMap

                this.put((String)key, clone);   // saves section to this map
            }
        }
    }
    
    @Override 
    public boolean equals(Object obj){
        try{
            Filter fr = (Filter)obj;
            return fr.getName().equals(this.name);
        } catch(ClassCastException err){
            return false;
        }
    }
    public String getOriginalName(){return originalName;}
    public String getName(){return name;}
    public String getConfigString(){return configString;}
    /**
     * Sets original name to current name.
     */
    public void setOriginalName(){originalName=name;}
    final public void setName(String value){
        name = value!=null?value:"";
    }
    final public void setConfigString(String value) {
        configString = value!=null?value:"";
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
    
    /**
     * Factory method to create a filter using a valid config string.
     * @param configString A valid config string usually found in a filter config file.
     * @return The fully initialized filter.
     */
    public static Filter parseFilter(String configString){
        String[] lines = configString.split("\n");    // splits config string by lines
        int N = lines.length;  // gets number of lines
        String sectionFormat = "(^\\s*\\[([\\w-]+)\\]\\s*$)";
        String propertyFormat = "(^\\s*([\\w-_]+)\\s*=([^\\n]*)$)";
        
        Pattern sectionPattern = Pattern.compile(sectionFormat);    // creates a pattern for sections
        Pattern propertyPattern = Pattern.compile(propertyFormat);    // creates a pattern for section properties
        Filter ftr = new Filter();  // creates new empty filter
        ftr.setConfigString(configString);  // sets the config string for new filter
        Matcher m = null;
        
        for(int i = 0; i<N;){ // loops through each line
            
            m = sectionPattern.matcher(lines[i]);   // matches the section pattern against this line
            if(m.matches()){    // checks if this line matches the section pattern
                String sectionName = m.group(2);    // gets the section name
                Map<String,String> propMap = new HashMap<String,String>();  // creates new property map for this section
                ftr.put(sectionName, propMap);    // creates new section
                
                i=i+1;  // advances next line
                while(i<N && !Pattern.matches(sectionFormat, lines[i])){   // checks if this line still matches a section format
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

                    propMap.put(key,value.toString());  // add this key:value to the property map of this section
                    } else 
                        ++i;
                }
            } else 
                ++i;
        }   
        return ftr;
    }
    /**
     * Creates a filter from a config file. This factory method also
     * sets the created filter name to file name.
     * @param configFilePath
     * @return
     * @throws IOException 
     */
    public static Filter parseFilter(Path configFilePath) throws IOException{
        String configStr = Files.readString(configFilePath);    // read file content
        
        Filter ftr = Filter.parseFilter(configStr); // parses a new filter
        String fileName = configFilePath.getFileName().toString();  // retrieves the file name
        fileName = fileName.substring(0,fileName.lastIndexOf("."));   // strip off the file extension
        ftr.setName(fileName);  // sets filter name to where the config file is saved
        ftr.setOriginalName();
        return ftr;
    }
    
    /**
     * Overrides this filter configs with local configs {@code filter} by:
     * <ol>
     * <li>Old colfig = new config is valuable ? new config : old config</li>
     * <li>Updates config string of this filter it self with {@link #updateConfigString()}.</li>
     * </ol>
     * @param filter Local filter to override on.
     */
    public void override(Filter filter){
        for(Object sectionKey : filter.keySet()){
            Map<String,String> section = (Map<String,String>)filter.get(sectionKey);    // gets map associated with this key
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
    
    public Filter clone() {
        Filter filter = (Filter)super.clone();
        // copying map
        return null;
    }
    
    
    public static void main(String[] args) throws IOException, Exception{
        
        test1();
        System.out.println("Test completed");
    }
    
    public static void test1() throws IOException{
        Map<String,String> map1 = new HashMap<String,String>();
        Map<String,String> map2 = new HashMap<String,String>();
        
        // initializes map1
        for(int i = 0; i<10; ++i)
            map1.put(""+i, "Hello "+(i+1));
        map2.putAll(map1);
        for(Object key : map1.keySet())
            System.out.println(key.toString()+" : "+map1.get(key));
        // modifies map2
        for(int i = 0; i<10; ++i)
            map2.replace(""+i, "Good bye "+(i-10));
        for(Object key : map1.keySet())
            System.out.println(key.toString()+" : "+map1.get(key));
        // SUMMARY: Map.putAll() does shallow copy
    }
    public static void test2() throws Exception{
        Map<String,String> map1 = new HashMap<String,String>();
        
        // initializes map1
        for(int i = 0; i<10; ++i)
            map1.put(""+i, "Hello "+(i+1));
        Map<String,String> map2 = new HashMap<String,String>(map1);
        for(Object key : map1.keySet())
            System.out.println(key.toString()+" : "+map1.get(key));
        // modifies map2
        for(int i = 0; i<10; ++i)
            map2.replace(""+i, "Good bye "+(i-10));
        for(Object key : map1.keySet())
            System.out.println(key.toString()+" : "+map1.get(key));
        
    }
    
}
