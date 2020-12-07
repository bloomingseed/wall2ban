/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.fail2ban;

import wall2ban.BashInterpreter;

/**
 * Ultimate DAO of the fail2ban application.
 * @author xceeded
 */
public class Fail2banContext {
    
    private ActionStore actionStore;
    private FilterStore filterStore;
    private JailStore jailStore;
    private BashInterpreter bi;
    
    public Fail2banContext() throws Exception{
        reloadContext();
        bi = new BashInterpreter();
    }
    
    public ActionStore getActionStore(){return actionStore;}
    public FilterStore getFilterStore(){return filterStore;}
    public JailStore getJailStore(){return jailStore;}
    
    private void reloadContext() throws Exception{
        actionStore = new ActionStore();
        filterStore = new FilterStore();
        jailStore = new JailStore();
    }
    
    public boolean isActivated() throws Exception{
        String command = "fail2ban-client status";
        return bi.executeRoot(command)==0;
    }
    public void activate() throws Exception{
        String command = "fail2ban-client start";
        if(bi.executeRoot(command)!=0)
            throw new Exception("Failed to start fail2ban-client");
        reloadContext();
    }
    public void deactivate() throws Exception{
        String command = "fail2ban-client stop";
        if(bi.executeRoot(command)!=0)
            throw new Exception("Failed to start fail2ban-client");
    }
    
    
    public static void main(String[] args) throws Exception{
        Fail2banContext dao = new Fail2banContext();
        System.out.println(dao.getJailStore().getDefaultJailConfig().toConfigString());
    }
    
}
