/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.fail2ban;

/**
 * Ultimate DAO of the fail2ban application.
 * @author xceeded
 */
public class Fail2banContext {
    
    private ActionStore actionStore;
    private FilterStore filterStore;
    private JailStore jailStore;
    
    public Fail2banContext() throws Exception{
        actionStore = new ActionStore();
        filterStore = new FilterStore();
        jailStore = new JailStore();
    }
    
    public ActionStore getActionStore(){return actionStore;}
    public FilterStore getFilterStore(){return filterStore;}
    public JailStore getJailStore(){return jailStore;}
    
    
    public static void main(String[] args) throws Exception{
        Fail2banContext dao = new Fail2banContext();
        System.out.println(dao.getJailStore().getDefaultJailConfig().toConfigString());
    }
    
}
