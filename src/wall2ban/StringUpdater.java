/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A tool to update a string line-by-line using regex.
 * <p>
 * Usage:
 * <ol>
 * <li> Specify the string to update as list of its lines and the pattern
 * for when matched, the mapped string should be replaced.</li>
 * <li> Optionally specify the line-index update method by setting the callback.
 * Default index update method is continuous increment.</li>
 * <li> Invoke {@link #update()} and retrieve the updated string by 
 * using the returned string or by calling {@link getUpdatedResult()}.</li>
 * </ol>
 * @author xceeded
 */
public class StringUpdater {
    /**
     * The index update method to call after regex'ed each line
     */
    protected Callback cb;      
    
    /**
     * Default implementation of the index update method, which is 
     * continuous increment.
     */
    protected class DefaultCallback implements Callback{  // 
        @Override
        public int handle(int index, String[] oldContent){
            return index+1;
        }
    }
    /**
     * The index update method interface.
     */
    public interface Callback{     
        int handle(int index, String[] oldContent);
    }
    
    /**
     * Old content as a list of its lines.
     */
    protected String[] oldContent;  // original content to be updated
    /**
     * Direction on which line to replace ({@code Pattern}) and what to replace ({@code String}).
     */
    protected Map<Pattern,String> updateSource; // specify which line and how it should be updated
    /**
     * The updated string after each call to {@link update()}.
     * @see #getUpdatedResult()
     */
    protected String updatedResult;
    
    /**
     * Basically initialize the tool with the callback being default one 
     * and the other fields being null.
     */
    public StringUpdater(){
        cb = new DefaultCallback(); // initialize default index update method
        oldContent = null;
        updateSource = null;
        updatedResult=null;
    }
    /**
     * Fully initialize the tool.
     * @param original String content to update as a list of its lines.
     * @param updateSource A map of which line in {@code original} to update ({@code Pattern}) and
     * what should be replaced into ({@code String}).
     * @param updateiProc The index update method to be used, which is called after each
     * time the regex matches to determine which line within {@code original} should it try-match next.
     */
    public StringUpdater(String[] original, Map<Pattern,String> updateSource, Callback updateiProc){
        this(); // first call default constructor to initialize resources
        oldContent = original;
        this.updateSource = updateSource;
        setCallback(updateiProc);  // use specified update index method if not null
    }   
    
    /**
     * Updates the {@code oldContent} using the {@code updateSource} mapping and
     * the {@code updateiProc} index update method.
     * @return The updated content.
     * @throws Exception If either {@code oldContent}, {@code updateSource} or {@code updateiProc} 
     * being {@code null}.
     */
    public String update() throws Exception{
        if(oldContent==null || updateSource == null || cb==null)
            throw new Exception("Argument exception");
        StringBuilder sb = new StringBuilder(); // initialize string builder
        // match each line with each pattern
        for(int i = 0; i<oldContent.length; ++i){
            // helper variable to see if the callback should be raised
            boolean raiseCallback=false;
            String lineContent=oldContent[i];    // the content to be stored; default to old line
            // try match each pattern to this line
            for(Pattern p : updateSource.keySet()){
                Matcher m = p.matcher(oldContent[i]);   // apply the pattern
                if(!m.matches())    // pattern doesnt match this line
                    continue;
                // pattern matches this line
                lineContent = updateSource.get(p);  // use the mapped line instead
                raiseCallback=true;     // telling that the callback should be raised
                break;  // stop applying pattern to this line
            }
            sb.append(lineContent).append("\n");   // stores this line content
            if(raiseCallback)
                i=cb.handle(i, oldContent)-1;   // minus one to complement the increment after the loop
        }
        updatedResult = sb.toString();  // store ultimate result
        return updatedResult+"";    // return a cloned string object
    }
    
    
    public String[] getOldContent(){return oldContent;}
    public Map<Pattern,String> getUpdateSource(){return updateSource;}
    public Callback getCallback(){return cb;}
    public String getUpdatedResult(){return updatedResult+"";}
    
    public void setOldContent(String[] content){oldContent=content;}
    public void setUpdateSource(Map<Pattern,String> source){updateSource=source;}
    final public void setCallback(Callback proc){
        cb=proc==null?new DefaultCallback():proc;
    }
    
    public static void main(String[] args) throws Exception{
        test1();
    }
    public static void test1() throws Exception{
        String content = "hello world\nbye world\nhello world";
        HashMap<Pattern, String> mapping = new HashMap<Pattern, String>();
        mapping.put(Pattern.compile("(^hello.*$)"), "this is bloomingseed\nbloomingseed has written this line.");
        StringUpdater su = new StringUpdater(content.split("\n"),mapping,null);
        System.out.println("Old:\n"+content+"\nNew:\n"+su.update());
    }
    
    
    
}
