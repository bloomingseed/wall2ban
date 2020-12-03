/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.fail2ban;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import wall2ban.IStore;
import wall2ban.Utilities;

/**
 * Data access class for fail2ban actions.
 * @see Action
 * @see #ActionStore()
 * @author xceeded
 */
public class ActionStore implements IStore<Action,String>{

    private List<Action> actions;
    /**
     * Path to fail2ban root folder.
     */
    private static final String FAIL2BAN_ROOT="/etc/fail2ban";
    /**
     * Path to the folder containing all fail2ban actions.
     * @see FAIL2BAN_ROOT
     */
    private static final String ACTIONS_FOLDER=FAIL2BAN_ROOT+"/action.d";
    /**
     * Reads and parses all actions in {@link ACTIONS_FOLDER}.
     */
    public ActionStore(){
        getAllActions();
    }
    
    @Override
    public List<Action> readAll() {
        return actions;
    }

    @Override
    public Action readByKey(String key) {
        for(Action action : actions)    
            if(action.getName().equals(key))    // checks if the action has same name as key
                return action;  // return the matching action
        return null;    // returns nothing
    }

    @Override
    public void create(Action entity) throws Exception {
        if(entity==null || actions.contains(entity)) // checks if such jail is null or has existed
            throw new Exception("Invalid jail");
        actions.add(entity);  // adds to jails list
        saveAction(entity);   // saves jail to disk
    }

    @Override
    public void update(Action entity) throws Exception {
        if(entity == null || !actions.contains(entity))
            throw new Exception("Invalid jail");
        Action oldAction = readByKey(entity.getName()); // gets jail with such name from jails list
        oldAction.override(entity);   // updates jail
        saveAction(oldAction);  // saves jail to disk
    }

    @Override
    public void delete(Action entity) throws Exception {
        if(entity == null || !actions.remove(entity))
            throw new Exception("Invalid jail");
        File saveFile = Paths.get(String.format(ACTIONS_FOLDER+"/%s.local",entity.getName())).toFile();   // gets config file of this jail
        boolean res = saveFile.delete();  // deletes save file
        if(!res)
            throw new Exception("Deleting action "+entity.getName()+" failed");
    }

    /**
     * Parses all action file from {@link ACTIONS_ROOT} to actions and 
     * initializes actions collection.
     */
    private void getAllActions() {
        actions = new ArrayList<Action>(); // creates new empty actions list
        
        File folder = Paths.get(ACTIONS_FOLDER).toFile();   // gets folder containing all actions
        FilenameFilter nameflt = new FilenameFilter(){
            @Override
            public boolean accept(File parent, String name){
                int i = name.lastIndexOf(".");
                String ext = i<0? "noExt" :name.substring(i); // retrieves the file extension
                return (i<0 || ext.equals(".conf")||ext.equals(".local"));
            }
        };  // filters only .conf and .local files
        File[] paths = folder.listFiles(nameflt);   // gets all action config file
        for(File filtp : paths){    // loops through each file
            Path path = filtp.toPath(); // gest file path
            try{
                Action action = Action.parseAction(path);   // parses a new action
                int i = actions.indexOf(action);   // gets index of this new action in list
                if(i<0) // checks if new action doesn't exist yet
                    actions.add(action);    // adds action to list
                else
                    actions.get(i).override(action);    // overrides old action with new one
            } catch(Exception err){
                System.out.println("Failed when parsing action at "+path.toString()+". Skipping this action..");
            }
        }  
    }
    private void saveAction(Action action) throws IOException{
        File configFile = Paths.get(ACTIONS_FOLDER+String.format("/%s.local",action.getName())).toFile();   // gets file to current action name
        if(configFile.exists()) // checks if such file exists
            configFile.delete();    
        configFile.createNewFile();
        Utilities.Utils.saveToFile(configFile.getPath(),action.toConfigString()); // saves content to file at path
        
        String oldName = action.getOriginalName();    // gets this action original name since last read
        if(oldName!=null && !oldName.equals(action.getName())){ // checks if the name has changed to different than original name
            File oldConfigFile = Paths.get(ACTIONS_FOLDER+String.format("/%s.local",oldName)).toFile();    // gets file to original name
            oldConfigFile.delete(); // deletes old file
        }
        action.setOriginalName(); // sets the original name for this action.
    }
    
    public static void main(String[] args) throws IOException, Exception{
        
        test1();
        System.out.println("Test completed");
    }
    
    public static void test1() throws IOException, Exception{
        ActionStore actionStore = new ActionStore();
        String config="[Definition]\n"
                + "failregex=^INFO: Login failed.\\.*$\n"
                + "ignoreregex=\n"
                + "";
        System.out.println(config);
        Action myAction = Action.parseAction(config);
        myAction.setName("my-action");
        actionStore.create(myAction);
        System.out.println(myAction.toConfigString());
        Map<String,String> defSection = myAction.get("Definition");
        defSection.replace("ignoreregex", "^INFO: Login failed by user xceeded.\\.*$");
        actionStore.update(myAction);
        myAction.setName("my-foo-action");
        actionStore.update(myAction);
        actionStore.delete(myAction);
    }
    
}
