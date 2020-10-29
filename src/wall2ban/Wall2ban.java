/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban;

import com.sun.security.auth.module.UnixSystem;

/**
 *
 * @author xceeded
 */
public class Wall2ban {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        try{
            UnixSystem sys = new UnixSystem();
            String cuser = sys.getUsername();
                if(cuser.equals("root")){
                    java.awt.EventQueue.invokeLater(new Runnable() {
                        public void run() {
                            new MainGUI().setVisible(true);
                        }
                    });
                }
                else
                    System.out.println("You need to run this program as root to proceed.");
        } catch(Exception err){
            err.printStackTrace();
        }
    }
    
}
