/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban;

import java.io.IOException;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A mediator helps execute shell command and retrieve response as String and exit code.
 * @author xceeded
 */
public class BashInterpreter {
    private ProcessBuilder pb;
    /**
     * Default location of terminal on Linux-based systems.
     */
    public final String BASH_LOCATION="/bin/bash";
    /**
     * List of commands that are actually executed.
     */
    private String[] commands;
    /**
     * Response after every call to {@link #execute()}. After each session, its value 
     * can be:
     * <ul>
     * <li>{@code String} - If last session produces any lines of output.</li>
     * <li>{@code String} - But an empty string if last session didn't produce any output.</li>
     * <li>{@code null} - If last session failed to start or before retrieving any output.
     * </ul>
     */
    private String response;
    /**
     * Errors generated after every call to {@link #execute()}. After each session, its value 
     * can be:
     * <ul>
     * <li>{@code String} - If last session produces any lines of output.</li>
     * <li>{@code String} - But an empty string if last session didn't produce any output.</li>
     * <li>{@code null} - If last session failed to start or before retrieving any output.
     * </ul>
     */
    private String errors;
    /**
     * Basically initializes the process builder to start bash terminal
     */
    public BashInterpreter(){
        pb = new ProcessBuilder();
        // commands to spawn bash terminal; last element is shell command
        commands= new String[]{BASH_LOCATION,"-c",""};
    }
    /**
     * Retrieves only the shell command that is executed against terminal
     * @return {@code String} - Shell command to be executed.
     */
    public String getCommand(){return commands[2];}
    /**
     * Sets the shell command to be executed next against the terminal.
     * @param cmd String representation of shell command
     */
    public void setCommand(String cmd){
        commands[2]=cmd;
        pb.command(commands);   // apply commands to pb
    }
    /**
     * Retrieves the response of the previous execution.
     * @return 
     * <ul>
     * <li>Response from terminal as {@code String}, or </li>
     * <li>{@code null} if previous execution failed. </li>
     * </ul>
     * @see #response
     */
    public String getResponse(){return response;}
    /**
     * Retrieves the errors of the previous execution.
     * @return 
     * <ul>
     * <li> Errors from terminal as {@code String}, or </li>
     * <li>{@code null} if previous execution failed. </li>
     * </ul>
     * @see #errors
     */
    public String getErrors(){return errors;}
    /**
     * Executes the configured command against the terminal. The response 
     * can be retrieved with {@link #getResponse()} method.
     * @return {@code int} - Exit code of the terminal after executing the command.
     * @throws IOException Communication with the terminal failed.
     * @throws Exception If {@code command} wasn't set properly.
     */
    public int execute() throws IOException, Exception{
        this.response = null;   // reset response to null and begin new session
        this.errors = null;     // reset errors to null and begin new session
        // if `command` is invalid
        if(commands[2]==null || commands[2].isEmpty() || commands[2].isBlank()){
            throw new Exception("Command not specified");
        }
        
        Process p = pb.start(); // start execution
        while(p.isAlive()) ;    // waits while process hasn't ended
        
        // retrieves output results
        Thread t1 = new Thread(new Runnable(){
            public void run(){
                Scanner pIn = new Scanner(p.getInputStream());
                // gets terminal outputs stream
                StringBuilder sb = new StringBuilder();
                try{
                    while(true)
                        sb.append(pIn.nextLine()).append("\n");
                } catch(NoSuchElementException err){}
                pIn.close();    // close the stream
                response = sb.toString();  // saves this session results
            }
        }),
                t2 = new Thread(new Runnable(){
                    public void run(){
                        // retrieves output results
                        Scanner pErr = new Scanner(p.getErrorStream());  // gets terminal errors stream
                        StringBuilder sb = new StringBuilder();
                        try{
                            while(true)
                                sb.append(pErr.nextLine()).append("\n");
                        } catch(NoSuchElementException err){}
                        pErr.close();    // close the stream
                        errors = sb.toString();  // saves this session results

                    }
                });
        // start read threads
        t1.run();
        t2.run();
        // join threads
        t1.join();
        t2.join();
        
        return p.exitValue();
    }
    
    /**
     * DEVELOPMENT: store the root password to call privileged commands.
     * */
    private static String ROOT_PASS="mynewbnscharactersnameislukie";
    /**
     * DEVELOPMENT ONLY: Execute specified shell command as root
     * @param cmd Shell command as {@code String}
     * @return Terminal response as {@code String}
     * @throws IOException If communication with terminal fails
     */
    public int executeRoot(String cmd) throws Exception{
        setCommand("echo "+ROOT_PASS+" | sudo -S "+cmd);
        return execute(); 
    }
    
    
    public static void main(String[] args){
        try {
            test2();
        } catch (Exception ex) {
            Logger.getLogger(BashInterpreter.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public static void test1(){
        BashInterpreter bi = new BashInterpreter();
        bi.setCommand("cal");
        try{
            bi.execute();
            String result = bi.getResponse();
            System.out.println(result);
        } catch(Exception err){
            err.printStackTrace();
        }
    }
    public static void test2() throws Exception{
        
        BashInterpreter bi = new BashInterpreter();
        bi.setCommand("iptables -L");
        bi.execute();
        System.out.println("Output: \n"+bi.getResponse());
        System.out.println("Errors: \n"+bi.getErrors());
        
    }
    
    
}
