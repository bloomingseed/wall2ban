/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban;

import java.awt.BorderLayout;
import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import wall2ban.fail2ban.Fail2banContext;
import wall2ban.fail2ban.Fail2banPanel;
import wall2ban.firewall.FirewallPanel;
import wall2ban.firewall.IPContext;

/**
 *
 * @author xceeded
 */
public class MainGUI extends JFrame{
    
    private FirewallPanel fwPanel;
    private Fail2banPanel f2bPanel;
    
    public MainGUI() throws Exception{
        super();
        initializeComponents();
    }
    
    
    public void initializeComponents() throws Exception{
        
        fwPanel = new FirewallPanel(this);
        f2bPanel = new Fail2banPanel(this);
        
        tbpane = new JTabbedPane();
        tbpane.addTab("Firewall", fwPanel);
        tbpane.addTab("Fai2ban", f2bPanel);
        
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(tbpane,BorderLayout.CENTER);
        setLocationRelativeTo(null);    // centers the form to screen
        pack();
    }
    
    
    
    
    public static void main(String[] args){
        try{
            BashInterpreter bi = BashInterpreter.getSingleton();
            MainGUI gui = new MainGUI();
            gui.setVisible(true);
        } catch(Exception err){
            err.printStackTrace();
        }
    }
    
    private JTabbedPane tbpane;
    
}
