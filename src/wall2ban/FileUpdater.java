/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban;

import static utils.Utilities.Utils;

import java.io.FileNotFoundException;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A tool to update a file content. Internally it uses {@link StringUpdater}.
 * <p>
 * How to use:
 * <ol>
 * <li>Specify the file to update and the mapping between the pattern
 * for line to be replaced and replacing string content.</li>
 * <li>Optionally specify the method to find next line after each 
 * replacement. The default is continuous increment.</li>
 * <li>Invoke {@link update()} method to swap file content to new content.</li>
 * </ol>
 * @author xceeded
 */
public class FileUpdater {
    private File oldFile;
    private StringUpdater supdater;
    
    public final String PREFIX = ".fileupdater";
    public final String SUFFIX = null;
    
    /**
     * Initializes the internal of the tool and leaves {@code oldFile} being {@code null}.
     */
    public FileUpdater(){
        supdater = new StringUpdater();
    }
    public FileUpdater(File oldFile, Map<Pattern,String> updateSource, StringUpdater.Callback cb) throws FileNotFoundException{
        this();     // basically initializes the tool
        setOldFile(oldFile);    
        supdater.setUpdateSource(updateSource);
        supdater.setCallback(cb);
        
    }
    
    /**
     * Get the }@code File} in which the old content will be replaced.
     * @return {@code File} - The file object containing the old content.
     */
    public File getOldFile(){return this.oldFile;}
    public StringUpdater getStringUpdater(){return this.supdater;}
    
    public void setOldFile(File file) throws FileNotFoundException {
        if(!file.exists() || !file.isFile())
            throw new FileNotFoundException();
        oldFile = file;
    }
    
    
    
    /**
     * Performs the update process then replace it with the old content in the file.
     * @throws FileNotFoundException
     * @throws IOException 
     */
    public void update() throws FileNotFoundException, IOException, Exception{
        // read all file contents and split into lines
        String[] oldContent = Files.readString(oldFile.toPath()).split("\n");
        
        supdater.setOldContent(oldContent); // initialize string updater's old content field
        String newContent = supdater.update();  // updates the old content
        
        File tmpDir = Paths.get(oldFile.getParent()).toFile();      // directory to hold temp file
        File tmpFile = File.createTempFile(PREFIX, SUFFIX, tmpDir); // create temp file
        
        // write new content to temp file
        BufferedWriter bw = new BufferedWriter(new FileWriter(tmpFile));
        bw.write(newContent);
        bw.close(); // close the writer and save changes
        
        // delete true file
        boolean isDeleted = oldFile.delete();   // delete old file
        if(!isDeleted)   // if didn't delete the old file
            throw new Exception("Failed to delete file");
        // rename tmp file to old file
        tmpFile.renameTo(oldFile);        
    }
    
    public static void main(String[] args) throws InterruptedException, IOException, Exception{
        
        test2();
        
    }
    public static void test1() throws InterruptedException{
        try {
            File srcFile = Paths.get(Utils.getWorkingFoler(),"foo.data").toFile();
            File tmpFile = File.createTempFile("."+srcFile.getName(), "tmp", srcFile.getParentFile());
            System.out.println(tmpFile.getAbsolutePath());
            BufferedWriter bw = new BufferedWriter(new FileWriter(tmpFile));
            for(int i = 0; i<10; ++i){
                bw.write("Hello "+i+"\n");
            }
            bw.close();
            System.out.println("Waiting 10 secs to delete "+srcFile.getAbsolutePath());
            Thread.sleep(10000);
            srcFile.delete();
            System.out.println("Deleted "+srcFile.getAbsolutePath());
            System.out.println(String.format("Changing %s to %s..",tmpFile.getAbsoluteFile(),srcFile.getAbsoluteFile()));
            if(tmpFile.renameTo(srcFile))
                System.out.println("Changed name");
            else
                System.out.println("Couldn't change name");
            
        } catch (IOException ex) {
            Logger.getLogger(FileUpdater.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public static void test2() throws IOException, Exception{
        
        HashMap<Pattern,String> updatesrc = new HashMap<Pattern,String>();
        String newValue = "say xceeded was here\n";
//                + "curl dev page\n"
//                + "start app\n"
//                + "open landing page";
        updatesrc.put(Pattern.compile("(^\\s*actionstart\\s*=(.*)$)"), "actionstart = "+newValue);
        File srcFile = Paths.get(Utils.getWorkingFoler(),"foo.data").toFile();
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
        FileUpdater fu = new FileUpdater(srcFile,updatesrc, cb);
        
        fu.update();
        
    }
}
