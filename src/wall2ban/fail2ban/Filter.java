/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.fail2ban;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import wall2ban.Utilities.Utils;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import wall2ban.StringUpdater;

/**
 * A Bean model representing a fail2ban filter.
 * @author xceeded
 */
public class Filter {
    /**
     * Name of the file containing this filter's config. Excluding the extension: .conf, .local.
     */
    private String name;
    private String failRegex, ignoreRegex, configString;
    /**
     * Specifies definitions in config file that will be stored as
     * the filter property.
     */
    private static final String[] knownDefs = new String[]{"failregex","ignoreregex"};
    
    public Filter(){
        name = failRegex = ignoreRegex = configString = "";
    }
    
    public Filter(String name, String failRegex, String ignoreRegex, String configString){
        setName(name);
        setFailRegex(failRegex);
        setIgnoreRegex(ignoreRegex);
        setConfigString(configString);
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
    public String getName(){return name;}
    public String getFailRegex(){return failRegex;}
    public String getIgnoreRegex(){return ignoreRegex;}
    public String getConfigString(){return configString;}
    
    final public void setName(String value){
        name = value!=null?value:"";
    }
    final public void setFailRegex(String value){
        failRegex = value!=null?value:"";
    }
    final public void setIgnoreRegex(String value){
        ignoreRegex = value!=null?value:"";
    }
    final public void setConfigString(String value) {
        configString = value!=null?value:"";
    }
    /**
     * Factory method to create a filter using a valid config string.
     * @param configString A valid config string usually found in a filter config file.
     * @return The fully initialized filter.
     */
    public static Filter parseFilter(String configString){
        String[] clines = configString.split("\n");    // splits config string by lines
        String format = "(^\\s*(%s)\\s*=([^\\n]*)$)";   // creates a format for a def pattern
        Filter ftr = new Filter();  // creates new empty filter
        ftr.setConfigString(configString);  // sets the config string for new filter
        
        for(int i = 0; i<clines.length; ++i){ // loops through each line
            // loops each pattern in known def for this line
            for(String def : knownDefs){ 
                Pattern p = Pattern.compile(String.format(format,def)); // creates the pattern for this def against a line
                Matcher m = p.matcher(clines[i]);    // matches the pattern against this line
                if(!m.matches())    // if pattern not match
                    continue;   // skips to next def
                
                // parses definition
                String defName = m.group(2);   // retrieves definition name
                StringBuilder sb = new StringBuilder(); // creates new string builder
                sb.append(m.group(3)).append("\n");  // append def value in this line
                // parses definition in next lines
                for(int j = i+1; j<clines.length;++j){
                    // regex to match the line over the definition
                    String sregx = "(^[\\s\\w-]+=\\s*[^\\n]$)";
                    if(!Pattern.matches(sregx, clines[j]))  // checks if reached over-the-definition line
                        sb.append(clines[j]).append("\n");  // append definition line
                    else{
                        --i;    // decreases here, increses latter
                        break;
                    }
                }
                
                String value = sb.toString();   // gets value of filter property
                switch(defName){
                    case "failregex":
                        ftr.setFailRegex(value);
                        break;
                    case "ignoreregex":
                        ftr.setIgnoreRegex(value);
                        break;
                }
                break;  // stops matching other definition
            }
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
        
        return ftr;
    }
    /**
     * Updates this config string of this filter using its properties.
     * @throws IllegalStateException If the config string of this filter hasn't been initialized.
     */
    public void updateConfigString() throws IllegalStateException {
        if(configString.isBlank())  // checks if config string has not been initialized
            throw new java.lang.IllegalStateException("Config string must be initialized before updating");
        
        // creates the mapping between new content and 
        // pattern of the line to be replaced
        HashMap<Pattern, String> mapping = new HashMap<Pattern, String>();
        
        String format = "(^\\s*(%s)\\s*=([^\\n]*)$)";   // creates a format for a def pattern
        for(String def : Filter.knownDefs){
            Pattern p = Pattern.compile(String.format(format,def));
            String contn = null;
            // determines the content to be mapped
            switch(def){
                case "failregex":
                    contn = "failregex = "+this.failRegex;
                    break;
                case "ignoreregex":
                    contn = "ignoreregex = "+this.ignoreRegex;
                    break;
            }
            mapping.put(p,contn);
        }
        
        // creates the index updating method
        StringUpdater.Callback cb = new StringUpdater.Callback(){
            public int handle(int index,String[] oldContent){
                int j;
                for(j = index+1; j<oldContent.length;++j){
                    // until find another '='
                    if(Pattern.matches("(^[^\\n]*=[^\\n]*$)", oldContent[j])){
                        break;
                    }                        
                }
                return j;
            }
        };
        
        StringUpdater supdater = new StringUpdater(this.configString.split("\n"),mapping,cb); // create the updater tool
        try {
            setConfigString(supdater.update()); // updates and replaces the old one
        } catch (Exception ex) {}   
    }
    
    public static void main(String[] args) throws IOException{
        
        test2();
        System.out.println("Test completed");
    }
    
    public static void test1() throws IOException{
        
        Path filePath = Paths.get(Utils.getWorkingFoler(),"/confsamples/filter/icmp-ping.conf");
        
        String fContent = Files.readString(filePath);
        Filter ftr = Filter.parseFilter(fContent);
        ftr.setFailRegex("Nothing");
        ftr.updateConfigString();
        
    }
    
    public static void test2() throws IOException{
        Path filePath = Paths.get(Utils.getWorkingFoler(),"/confsamples/filter/icmp-ping.conf");
        Filter ftr = Filter.parseFilter(filePath);
        
    }
    
}
