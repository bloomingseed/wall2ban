/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.fail2ban;

import com.sun.security.auth.module.UnixSystem;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import wall2ban.BashInterpreter;
import wall2ban.IStore;
import wall2ban.Utilities.Utils;

/**
 * Data access class for fail2ban jails.
 * @see Jail
 * @see #JailStore()
 * @author xceeded
 */
public class JailStore implements IStore<Jail,Object>{
    /**
     * Full list of jails configured in the system.
     */
    private List<Jail> jails;
    /**
     * Sublist of jails being active.
     */
    private Map<Jail,List<String>> activeJails;
    /**
     * Default config defined for all jails.
     */
    private DefaultJailConfig jailConfig;
    /**
     * Interpreter for bash terminal to execute commands.
     */
    private BashInterpreter bi;
    /**
     * String representation of file path to root folder for fail2ban-client.
     */
    private static final String FAIL2BAN_ROOT="/etc/fail2ban";
    /**
     * String representation of file path to jail folder for fail2ban-client.
     * @see #FAIL2BAN_ROOT
     */
    private static final String JAILS_FOLDER = FAIL2BAN_ROOT+"/jail.d";
    /**
     * Default constructor for the jail DAO. The constructor does:
     * <ol>
     * <li>Reads and overrides jails found in {@code jail.(config|local)} in {@link FAIL2BAN_ROOT} folder 
     * and all {@code *.(config|local)} files in {@link JAILS_FOLDER}.</li>
     * <li>Moves all jails into their separate files in {@link JAILS_FOLDER};
     * leaves only default jail configurations in {@code jail.(config|local)} in {@link FAIL2BAN_ROOT} folder.</li>
     * </ol>
     * @throws IOException If reading some file failed.
     * @throws Exception  If failed to get permission to create and delete file.
     * @see #getAllJails()
     * @see #cleanUp()
     */
    public JailStore() throws IOException, Exception {
        bi = new BashInterpreter();
        getAllJails();  
        getAllActiveJails();
        updateBannedIps();
        cleanUp();
    }
    
    public DefaultJailConfig getDefaultJailConfig(){return jailConfig;}
    /**
     * Reads and parses all jails from {@code jail.(config|local)} in {@link FAIL2BAN_ROOT} folder 
     * and in all {@code *.(config|local)} files in {@link JAILS_FOLDER}.
     * @see #parseJailConfig(File)
     */
    private void getAllJails() {
        jails = new ArrayList<Jail>();  // creates new empty jails list
        
        List<File> files = new LinkedList<File>();  // creates empty list of files to parse
        File jcFile = null; // declares the file reference
        jcFile = Paths.get(FAIL2BAN_ROOT+"/jail.conf").toFile();    // gets jail.conf file
        if(jcFile.exists()) // checks if jail.conf file exists
            files.add(jcFile);   // adds to files to read
        jcFile = Paths.get(FAIL2BAN_ROOT+"/jail.local").toFile();   // gets jail.local file
        if(jcFile.exists())   // checks if local config file exists
            files.add(jcFile); // adds local config file to files list
                
        File folder = Paths.get(JAILS_FOLDER).toFile();   // gets folder containing custom jails
        FilenameFilter flt = new FilenameFilter(){
            public boolean accept(File parent, String name){
                int i = name.lastIndexOf(".");
                String ext = i<0? "noExt": name.substring(i); // gets the file extension
                return (ext.equals(".conf")||ext.equals(".local"));
            }
        };  // creates file filter to get only .conf and .local files
        File[] customFiles = folder.listFiles(flt); // gets such file from folder
        
        for(File file : files)
            try{
                parseJailConfig(file); // parses jail.conf and jail.local
            } catch(Exception err){
                System.out.println("Failed when parsing jail at "+file.getPath()+". Skipping this jail..");
            }
        for(File file : customFiles)
            try{
                parseJailConfig(file); // parses each custom jail in jail.d
            }  catch(Exception err){
                System.out.println("Failed when parsing jail at "+file.getPath()+". Skipping this jail..");
            }
        
    }
    /**
     * Parses a jail from the {@code configFile} then either add new jail
     * to jails list or override old jail with the new one.
     * @param configFile The file containing jail config.
     * @throws IOException If reading the {@code configFile} failed.
     * @throws Exception If the parsed jail contains invalid config that can not be overridden on old jail.
     * @see Jail#parseJail(Path)
     */
    private void parseJailConfig(File configFile) throws IOException, Exception {        
        String content = Files.readString(configFile.toPath());
        String[] lines = content.split("\n");
        int N = lines.length;
        String sectionFormat = "(^\\s*\\[([\\w-]+)\\]\\s*$)";   // regex for line of section
        Pattern sectionPattern = Pattern.compile(sectionFormat);    // creates a pattern for sections
        
        StringBuilder defaultJailBuilder = new StringBuilder();   // builder for jail content
        StringBuilder jailBuilder = new StringBuilder();   // builder for jail content
        
        for(int i = 0; i<N;){
            
            Matcher m = sectionPattern.matcher(lines[i]);   // matches the section pattern against this line
            if(m.matches()){    // checks if this line matches the section pattern
                String sectionName = m.group(2);    // gets the section name
                jailBuilder.append(lines[i]).append("\n");  // adds the section line to builder
                i=i+1;  // advances next line
                while(i<N && !Pattern.matches(sectionFormat, lines[i]))     // while this line isn't section line and not out of line
                    jailBuilder.append(lines[i++]).append("\n");
                
                if(sectionName.equals("DEFAULT")||sectionName.equals("INCLUDES")){
                    // parse sbuilder content as DefaultJailConfig
                    defaultJailBuilder.append(jailBuilder.toString()).append("\n");
                }
                else{
                    // parse sbuilder content as jail config
                    try{
                        Jail jail = Jail.parseJail(jailBuilder.toString());
                        int index = jails.indexOf(jail);    // gets location of new jail in jails list
                        if(index<0) // checks if new jail hasn't exists yet
                            jails.add(jail);
                        else 
                            jails.get(index).override(jail);    // adds override new jail
                        
                    } catch(Exception err){
                        err.printStackTrace();  // logs error to console then continue
                    }
                }
                jailBuilder = new StringBuilder();  // creates new string builder
            }
            else 
                ++i;
            
        }
        String djailCString = defaultJailBuilder.toString();    // gets default jail config string
        if(!djailCString.isBlank()){    // checks if defaul jail builder has some content
            DefaultJailConfig newJailConfig = DefaultJailConfig.parseDefaultJailConfig(djailCString);
            if(jailConfig == null)  // checks if default jail config has been created yet
                jailConfig = newJailConfig; 
            else
                jailConfig.override(newJailConfig); // override with new default jail config
        }
    }
    /**
     * Delete jail.conf, write default configs to jail.local and write all jails to proper files in jail.d.
     * @throws IOException If writing jail to file failed.
     * @throws Exception If failed to get permission.
     * @see getPermission()
     */
    private void cleanUp() throws IOException, Exception{
        getPermission();    // gets write permission to all files needed 
        // TODO: use multithreading
        File jailConfigFile = Paths.get(FAIL2BAN_ROOT+"/jail.conf").toFile();
        File jailLocalFile = Paths.get(FAIL2BAN_ROOT+"/jail.local").toFile();
        if(jailConfigFile.exists())
            jailConfigFile.delete();    // deletes jail.conf from disk
        if(jailLocalFile.exists())  // checks if jail.local exists
            jailLocalFile.delete(); // deletes jail.local
        jailLocalFile.createNewFile();  // creates jail.local
        Utils.saveToFile(jailLocalFile.getPath(),this.jailConfig.getConfigString());  // writes default jail config to jail.local
        
        
        Map<File,String> customJailFile = new HashMap<File,String>();     // creates new list of jail files
        for(Jail jail : jails){
            saveJail(jail);
        }
    }
    
    private void getAllActiveJails() throws Exception{
        activeJails = new HashMap<Jail,List<String>>(); // creates empty list
        String command = "fail2ban-client status";  // defines the shell command
        if(bi.executeRoot(command)!=0)  // executes command then checks if it failed
            throw new Exception("Failed to get fail2ban status");
        
        String[] resLines = bi.getResponse().split("\n"); // gets and splits command response by lines
        String resLine = resLines[resLines.length-1];   // gets last response line 
        String pattern = "((^[^\\n]*Jail list:\\s*([\\w-\\s,]+)\\s*$))";   // defines regex pattern to get active jails
        Matcher m = Pattern.compile(pattern).matcher(resLine);
        if(!m.matches())    // matches the response against pattern then checks if it matches
            throw new Exception("Failed to match regex pattern.");
        
        String jailsList = m.group(2).split("[^\\n]*Jail list:\\s*")[1];  // gets the string part of jails name
        String[] jailNames = jailsList.split(",\\s*");  // splits jail names in jails list
        for(String jailName : jailNames){
            Jail jail = readByKey(jailName); // gets the jail by its name
            if(jail==null)  // checks if it doesn't listed
                throw new Exception("Failed to get jail "+jailName);
            activeJails.put(jail,null);  //adds it to list of active jails
        }
                
    }
    
    private void saveJail(Jail jail) throws IOException{
        File configFile = Paths.get(JAILS_FOLDER+String.format("/%s.local",jail.getName())).toFile();   // gets file to current jail name
        if(configFile.exists()) // checks if such file exists
            configFile.delete();    
        configFile.createNewFile();
        Utils.saveToFile(configFile.getPath(),jail.toConfigString()); // saves content to file at path
        
        String oldName = jail.getOriginalName();    // gets this jail original name since last read
        if(oldName!=null && !oldName.equals(jail.getName())){ // checks if the name has changed to different than original name
            File oldConfigFile = Paths.get(JAILS_FOLDER+String.format("/%s.local",oldName)).toFile();    // gets file to original name
            oldConfigFile.delete(); // deletes old file
        }
        jail.setOriginalName(); // sets the original name for this jail.
    }
    /**
     * DEVELOPMENT ONLY: Gets write permission to jail.conf, jail.local and all files within jail.d.
     * <p>
     * Remove this file and requires user to run as root to get permission in production.
     * @throws Exception If set owner or mode command failed.
     */
    private void getPermission() throws Exception{
        UnixSystem sys = new UnixSystem();
        String cuser = sys.getUsername();
        BashInterpreter bi = new BashInterpreter();
        String setOwnerCommand = String.format("chown %s -R %s",cuser,FAIL2BAN_ROOT);
        if(bi.executeRoot(setOwnerCommand)!=0)
            throw new Exception("Failed to set owner permission");
        String setPermissionCommand = String.format("chmod 771 -R %s",FAIL2BAN_ROOT);
        if(bi.executeRoot(setPermissionCommand)!=0)
            throw new Exception("Failed to set mode permission");
        
    }
    /**
     * Updates list of banned IPs of {@link activeJails}.
     */
    public void updateBannedIps() throws Exception{
        for(Map.Entry<Jail,List<String>> entry : activeJails.entrySet()){
            String command = "fail2ban-client status "+entry.getKey().getName();  // defines the shell command
            if(bi.executeRoot(command)!=0)  // executes the command then checks if it failed
                throw new Exception("Failed to get status of "+entry.getKey().getName()); 
            String[] resLines = bi.getResponse().split("\n");   // splits response by lines
            // gets last line then takes part containing list of banned ips
            String[] ipLine = resLines[resLines.length-1].split("[^\\n]*Banned IP list:\\s*");
            
            List<String> ipList = new ArrayList<String>();
            try{
                String ipsString = ipLine[1];   // gets second part of ipLine containing ips
                String[] ips = ipsString.split("\\s+");    // splits ip list to array
                for(String ip : ips)    // loops through each ip
                    ipList.add(ip); // adds to list
            } catch(java.lang.ArrayIndexOutOfBoundsException err){  // in case failed to get ips string
                System.out.println(entry.getKey().getName()+" has no banned IPs");
            }
            entry.setValue(ipList);    // sets the banned IPs to for this jail
        }
    }
    
    
    @Override
    public List<Jail> readAll() {
        return jails;
    }
    
    public Map<Jail,List<String>> readActiveJails(){ return activeJails;}

    @Override
    public Jail readByKey(Object key) {
        for(Jail jail : jails)  // loops through each jail in list
            if(jail.getName().equals(key))  // checks if this jail has same name as key
                return jail;    // returns this jail
        return null;    // returns nothing
    }

    public Map.Entry<Jail,List<String>> readActiveByKey(Object key){
        for(Map.Entry<Jail,List<String>> entry : activeJails.entrySet())  // loops through each jail in list
            if(entry.getKey().getName().equals(key))  // checks if this jail has same name as key
                return entry;    // returns this jail
        return null;    // returns nothing
    }
    
    @Override
    public void create(Jail entity) throws Exception {
        if(entity==null || jails.contains(entity)) // checks if such jail is null or has existed
            throw new Exception("Invalid jail");
        jails.add(entity);  // adds to jails list
        saveJail(entity);   // saves jail to disk
        
    }

    
    @Override
    public void update(Jail entity) throws Exception {
        if(entity == null || !jails.contains(entity))
            throw new Exception("Invalid jail");
        Jail oldJail = readByKey(entity.getName()); // gets jail with such name from jails list
        oldJail.override(entity);   // updates jail
        saveJail(oldJail);  // saves jail to disk
    }

    @Override
    public void delete(Jail entity) throws Exception {
        if(entity == null || !jails.remove(entity))
            throw new Exception("Invalid jail");
        File saveFile = Paths.get(String.format(JAILS_FOLDER+"/%s.local",entity.getName())).toFile();   // gets config file of this jail
        saveFile.delete();  // deletes save file
    }
    
    /**
     * Manually bans an ip for a specific jail.
     * @param jail Jail to ban.
     * @param ip IP to be banned.
     * @throws java.lang.Exception If ban action failed.
     */
    public void banJail(Jail jail, String ip) throws Exception{
        
        String command = String.format("fail2ban-client set %s banip %s",jail.getName(),ip);
        if(bi.executeRoot(command)!=0)
            throw new Exception(String.format("Failed to ban IP %s for jail %s",ip,jail.getName()));
        
    }
    
    /**
     * Manually unbans an ip for a specific jail.
     * @param jail Jail to unban.
     * @param ip IP to be unbanned.
     * @throws java.lang.Exception If unban action failed.
     */
    public void unbanJail(Jail jail, String ip) throws Exception{
        
        String command = String.format("fail2ban-client set %s unbanip %s",jail.getName(),ip);
        if(bi.executeRoot(command)!=0)
            throw new Exception(String.format("Failed to unban IP %s for jail %s",ip,jail.getName()));
        
    }
    
    /**
     * Unbans all IPs in all active jails.
     * @throws java.lang.Exception If unban all failed.
     */
    public void unbanAll() throws Exception{
        String command = String.format("fail2ban-client unban --all");
        if(bi.executeRoot(command)!=0)
            throw new Exception("Failed to unban all");
        
    }
    
    
    public static void main(String[] args) throws IOException, Exception{
        
        test3();
        System.out.println("Test completed");
    }
    
    public static void test1() throws IOException, Exception{
        JailStore jailStore = new JailStore();
        String config="[my-jail]\n"
                + "enabled=false\n"
                + "logpath=\n"
                + "backend=\n"
                + "";
        System.out.println(config);
        Jail myJail = Jail.parseJail(config);
        jailStore.create(myJail);
        System.out.println(myJail.toConfigString());
        myJail.replace("logpath", "/etc/my-jail.log");
        jailStore.update(myJail);
        myJail.setName("my-foo-jail");
        jailStore.update(myJail);
        jailStore.delete(myJail);
    }
    public static void test2() throws IOException, Exception{
        
        JailStore jailStore = new JailStore();
        for(Map.Entry<Jail,List<String>> entry : jailStore.readActiveJails().entrySet()){
            Jail jail = entry.getKey();
            List<String> bannedIps = entry.getValue();
            System.out.println(jail.getName());
            for(String ip : bannedIps)
                System.out.print(ip+" ");
            System.out.println();
        }
    }
    public static void test3() throws Exception{
        JailStore jailStore = new JailStore();
        String banip = "10.0.11.11";
        // display active jails and banned ips
        for(Map.Entry<Jail,List<String>> entry : jailStore.readActiveJails().entrySet()){
            Jail jail = entry.getKey();
            List<String> bannedIps = entry.getValue();
            System.out.println(jail.getName());
            for(String ip : bannedIps)
                System.out.print(ip+" ");
            System.out.println();
        }
        
        Jail banjail = jailStore.readActiveByKey("icmp-ping").getKey();
        jailStore.banJail(banjail, banip);
        // display active jails and banned ips
        for(Map.Entry<Jail,List<String>> entry : jailStore.readActiveJails().entrySet()){
            Jail jail = entry.getKey();
            List<String> bannedIps = entry.getValue();
            System.out.println(jail.getName());
            for(String ip : bannedIps)
                System.out.print(ip+" ");
            System.out.println();
        }
        
        jailStore.unbanJail(banjail, "10.0.11.11");
        jailStore.banJail(banjail, banip);
        // display active jails and banned ips
        for(Map.Entry<Jail,List<String>> entry : jailStore.readActiveJails().entrySet()){
            Jail jail = entry.getKey();
            List<String> bannedIps = entry.getValue();
            System.out.println(jail.getName());
            for(String ip : bannedIps)
                System.out.print(ip+" ");
            System.out.println();
        }
        
        jailStore.unbanAll();
        jailStore.banJail(banjail, banip);
        // display active jails and banned ips
        for(Map.Entry<Jail,List<String>> entry : jailStore.readActiveJails().entrySet()){
            Jail jail = entry.getKey();
            List<String> bannedIps = entry.getValue();
            System.out.println(jail.getName());
            for(String ip : bannedIps)
                System.out.print(ip+" ");
            System.out.println();
        }
    }
}

