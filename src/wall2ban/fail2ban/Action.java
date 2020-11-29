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
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import wall2ban.StringUpdater;
import wall2ban.Utilities;

/**
 * A Bean model representing a fail2ban action.
 * @author xceeded
 */
public class Action extends HashMap<String,Map<String,String>>{
    
    private String originalName;
    private String name, actionStart, actionStop, actionBan, actionUnban, configString;
    /**
     * Specifies definitions in config file that will be stored as
     * the action property.
     */
    private static final String[] knownDefs = new String[]{"actionstart", "actionstop", "actionban", "actionunban"};
    
    public Action(){
        super();
    }
    
    @Override 
    public boolean equals(Object obj){
        try{
            Action act = (Action)obj;
            return act.getName().equals(this.name);
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
    public void setName(String value){
        name = value!=null?value:"";
    }
    public void setConfigString(String value){
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
     * Creates new action with properties set by the {@code configString}.
     * @param configString The action configuration string found in action files.
     * @return New action corresponds to the {@code configString}.
     */
    public static Action parseAction(String configString){
        String[] lines = configString.split("\n");    // splits config string by lines
         int N = lines.length;  // gets number of lines
        String sectionFormat = "(^\\s*\\[([\\w-]+)\\]\\s*$)";
        String propertyFormat = "(^\\s*([\\w-_]+)\\s*=([^\\n]*)$)";
        
        Pattern sectionPattern = Pattern.compile(sectionFormat);    // creates a pattern for sections
        Pattern propertyPattern = Pattern.compile(propertyFormat);    // creates a pattern for section properties
        Action act = new Action();  // creates new empty action
        act.setConfigString(configString);  // sets the config string for new action
        Matcher m = null;
        
        for(int i = 0; i<N;){ // loops through each line
            
            m = sectionPattern.matcher(lines[i]);   // matches the section pattern against this line
            if(m.matches()){    // checks if this line matches the section pattern
                String sectionName = m.group(2);    // gets the section name
                Map<String,String> propMap = new HashMap<String,String>();  // creates new property map for this section
                act.put(sectionName, propMap);    // creates new section
                
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
        return act;  
    }
    
    
    /**
     * Creates new action with properties set by the the action configuration file at {@code configFilePath}.
     * @param configFilePath Path to the action configuration file.
     * @return New action corresponds to the {@code configFilePath}.
     */
    public static Action parseAction(Path configFilePath) throws IOException{
        String configStr = Files.readString(configFilePath);    // read file content
        
        Action act = Action.parseAction(configStr); // parses a new action
        String fileName = configFilePath.getFileName().toString();  // retrieves the file name
        fileName = fileName.substring(0,fileName.lastIndexOf("."));   // strip off the file extension
        act.setName(fileName);  // sets action name to where the config file is saved
        act.setOriginalName();
        return act;
    }
    
    /**
     * Overrides this action configs with local configs {@code ction} by:
     * <ol>
     * <li>Old colfig = new config is valuable ? new config : old config</li>
     * <li>Updates config string of this action it self with {@link #updateConfigString()}.</li>
     * </ol>
     * @param action Local action to override on.
     */
    public void override(Action action){
        for(Object sectionKey : action.keySet()){
            Map<String,String> section = (Map<String,String>)action.get(sectionKey);    // gets map associated with this key
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
    
    public static void main(String[] args) throws IOException{
        test3();
    }
    
    public static void test3() throws IOException{
        Path folder = Paths.get(Utilities.Utils.getWorkingFoler(),"/confsamples/action/");
        
        FilenameFilter flt = new FilenameFilter(){
            public boolean accept(File parent, String name){
                String ext = name.substring(name.lastIndexOf(".")); // retrieves the file extension
                return (ext.equals(".conf"));
            }
        };  // actions only .conf files
        File[] paths = folder.toFile().listFiles(flt);
        ArrayList<Action> actionList = new ArrayList<Action>();
        for(File filtp : paths){
            actionList.add(Action.parseAction(Paths.get(filtp.getAbsolutePath())));
        }
        
        flt = new FilenameFilter(){
            public boolean accept(File parent, String name){
                String ext = name.substring(name.lastIndexOf(".")); // retrieves the file extension
                return (ext.equals(".local"));
            }
        };  // actions only .local files
        paths = folder.toFile().listFiles(flt);
        for(File filtp : paths){
            Action _flt = Action.parseAction(Paths.get(filtp.getAbsolutePath()));
            int i = actionList.indexOf(_flt);   // gets index of this new action in list
            if(i<0)
                actionList.add(_flt);
            else
                actionList.get(i).override(_flt);
                
        }        
    }
    
}
