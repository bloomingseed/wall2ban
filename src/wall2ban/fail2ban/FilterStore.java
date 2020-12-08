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
import wall2ban.IStore;
import utils.Utilities;

/**
 * Data access class for fail2ban filters.
 * @see Filter
 * @see #FilterStore()
 * @author xceeded
 */
public class FilterStore implements IStore<Filter,String>{

    private List<Filter> filters;
    /**
     * Path to fail2ban root folder.
     */
    private static final String FAIL2BAN_ROOT="/etc/fail2ban";
    /**
     * Path to the folder containing all fail2ban filters.
     * @see #FAIL2BAN_ROOT
     */
    private static final String FILTERS_FOLDER=FAIL2BAN_ROOT+"/filter.d";
    /**
     * Reads and parses all filters found in {@link FILTERS_FOLDER}.
     * @see #getAllFilters()
     */
    public FilterStore() {
        getAllFilters();
    }
    
    @Override
    public List<Filter> readAll() {
        return filters;
    }

    @Override
    public Filter readByKey(String key) {
        for(Filter filter : filters)    
            if(filter.getName().equals(key))    // checks if the filter has same name as key
                return filter;  // return the matching filter
        return null;    // returns nothing
    }

    @Override
    public void create(Filter entity) throws Exception {
        if(entity==null || filters.contains(entity)) // checks if such jail is null or has existed
            throw new Exception("Invalid jail");
        filters.add(entity);  // adds to jails list
        saveFilter(entity);   // saves jail to disk
    }

    @Override
    public void update(Filter entity) throws Exception {
        if(entity == null || !filters.contains(entity))
            throw new Exception("Invalid jail");
        Filter oldFilter = readByKey(entity.getName()); // gets jail with such name from jails list
        oldFilter.override(entity);   // updates jail
        saveFilter(oldFilter);  // saves jail to disk
    }

    @Override
    public void delete(Filter entity) throws Exception {
        if(entity == null || !filters.remove(entity))
            throw new Exception("Invalid jail");
        File saveFile = Paths.get(String.format(FILTERS_FOLDER+"/%s.local",entity.getName())).toFile();   // gets config file of this jail
        boolean res = saveFile.delete();  // deletes save file
        if(!res)
            throw new Exception("Deleting filter "+entity.getName()+" failed");
    }

    /**
     * Parses all filter file from {@link FILTERS_ROOT} to filters and 
     * initializes filters collection.
     * @see Filter#parseFilter(Path)
     */
    private void getAllFilters() {
        filters = new ArrayList<Filter>(); // creates new empty filters list
        
        File folder = Paths.get(FILTERS_FOLDER).toFile();   // gets folder containing all filters
        FilenameFilter nameflt = new FilenameFilter(){
            @Override
            public boolean accept(File parent, String name){
                int i = name.lastIndexOf(".");
                String ext = i<0? "noExt" :name.substring(i); // retrieves the file extension
                return (i<0 || ext.equals(".conf")||ext.equals(".local"));
            }
        };  // filters only .conf and .local files
        File[] paths = folder.listFiles(nameflt);   // gets all filter config file
        for(File filtp : paths){    // loops through each file
            Path path = filtp.toPath(); // gest file path
            try{
                Filter filter = Filter.parseFilter(path);   // parses a new filter
                int i = filters.indexOf(filter);   // gets index of this new filter in list
                if(i<0) // checks if new filter doesn't exist yet
                    filters.add(filter);    // adds filter to list
                else
                    filters.get(i).override(filter);    // overrides old filter with new one
            } catch(IOException err){
                System.out.println("Failed when parsing filter at "+path.toString()+". Skipping this filter..");
            }
        }  
    }
    private void saveFilter(Filter filter) throws IOException{
        File configFile = Paths.get(FILTERS_FOLDER+String.format("/%s.local",filter.getName())).toFile();   // gets file to current filter name
        if(configFile.exists()) // checks if such file exists
            configFile.delete();    
        configFile.createNewFile();
        Utilities.Utils.saveToFile(configFile.getPath(),filter.toConfigString()); // saves content to file at path
        
        String oldName = filter.getOriginalName();    // gets this filter original name since last read
        if(oldName!=null && !oldName.equals(filter.getName())){ // checks if the name has changed to different than original name
            File oldConfigFile = Paths.get(FILTERS_FOLDER+String.format("/%s.local",oldName)).toFile();    // gets file to original name
            oldConfigFile.delete(); // deletes old file
        }
        filter.setOriginalName(); // sets the original name for this filter.
    }
    
    public static void main(String[] args) throws IOException, Exception{
        
        test1();
        System.out.println("Test completed");
    }
    
    public static void test1() throws IOException, Exception{
        FilterStore filterStore = new FilterStore();
        String config="[Definition]\n"
                + "failregex=^INFO: Login failed.\\.*$\n"
                + "ignoreregex=\n"
                + "";
        System.out.println(config);
        Filter myFilter = Filter.parseFilter(config);
        myFilter.setName("my-filter");
        filterStore.create(myFilter);
        System.out.println(myFilter.toConfigString());
        Map<String,String> defSection = myFilter.get("Definition");
        defSection.replace("ignoreregex", "^INFO: Login failed by user xceeded.\\.*$");
        filterStore.update(myFilter);
        myFilter.setName("my-foo-filter");
        filterStore.update(myFilter);
        filterStore.delete(myFilter);
    }
    
}
