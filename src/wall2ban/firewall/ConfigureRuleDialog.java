/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.firewall;

import java.awt.Frame;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;

/**
 *
 * @author Admin
 */
public class ConfigureRuleDialog extends javax.swing.JDialog {
private boolean formResult;
private IPRule rule;
private Frame parent;
    /**
     * Creates new form CreateRuleForm2
     */
    public ConfigureRuleDialog(java.awt.Frame parent, boolean modal, IPRule rule, String chainName) {
        super(parent, modal);
        initComponents();
        this.parent = parent;   // saves parent frame
        this.rule = new IPRule(rule);   // creates hard-copy from input rule
        
        this.chainLabel.setText(chainName); // sets chain name
        String buttonLabel = rule==null?"Create":"Update";  // initializes proper button label
        this.primaryButton.setText(buttonLabel);    // sets primary button label
        bindsData();    // updates view
    }
    public boolean getFormResult(){return this.formResult;}
    public IPRule getRule(){return rule;}
    /**
     * Extracts data from encapsulated rule and updates
     * to view components.
     */
    public void bindsData(){
        this.targetTextField.setText(rule.getTarget());
        this.sourceIpTextField.setText(rule.getSourceIp());
        this.sourcePortTextField.setText(""+rule.getSourcePort());
        this.protocolTextField.setText(rule.getProtocol());
        this.destinationIpTextField.setText(rule.getDestinationIp());
        this.destinationPortTextField.setText(""+rule.getDestinationPort());
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        protocolTextField = new javax.swing.JTextField();
        destinationIpTextField = new javax.swing.JTextField();
        chainLabel = new javax.swing.JLabel();
        destinationPortTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        dportlabel = new javax.swing.JLabel();
        targetTextField = new javax.swing.JTextField();
        sourceIpTextField = new javax.swing.JTextField();
        sourcePortTextField = new javax.swing.JTextField();
        jLabel7 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        jPanel2 = new javax.swing.JPanel();
        primaryButton = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        protocolTextField.setText("jTextField1");
        protocolTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                protocolTextFieldFocusLost(evt);
            }
        });

        destinationIpTextField.setText("jTextField1");
        destinationIpTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                destinationIpTextFieldFocusLost(evt);
            }
        });

        chainLabel.setText("chain name");

        destinationPortTextField.setText("jTextField1");
        destinationPortTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                destinationPortTextFieldFocusLost(evt);
            }
        });

        jLabel2.setText("Source IP:");

        jLabel3.setText("Source Port:");

        jLabel4.setText("Protocol:");

        jLabel5.setText("Destination IP:");

        dportlabel.setText("Destination Port:");

        targetTextField.setText("jTextField1");
        targetTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                targetTextFieldFocusLost(evt);
            }
        });

        sourceIpTextField.setText("jTextField1");
        sourceIpTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                sourceIpTextFieldFocusLost(evt);
            }
        });

        sourcePortTextField.setText("jTextField1");
        sourcePortTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                sourcePortTextFieldFocusLost(evt);
            }
        });

        jLabel7.setText("Target:");

        jLabel8.setText("Chain:");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel4, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel5, javax.swing.GroupLayout.DEFAULT_SIZE, 123, Short.MAX_VALUE)
                    .addComponent(dportlabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel8, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel7, javax.swing.GroupLayout.DEFAULT_SIZE, 123, Short.MAX_VALUE))
                .addGap(12, 12, 12)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(sourceIpTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 146, Short.MAX_VALUE)
                    .addComponent(targetTextField)
                    .addComponent(sourcePortTextField)
                    .addComponent(protocolTextField)
                    .addComponent(destinationIpTextField)
                    .addComponent(destinationPortTextField)
                    .addComponent(chainLabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(chainLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel8, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(targetTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(sourceIpTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(sourcePortTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(protocolTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(destinationIpTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(dportlabel, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(destinationPortTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        primaryButton.setText("Create");
        primaryButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                primaryButtonActionPerformed(evt);
            }
        });

        cancelButton.setText("Cancel");
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGap(30, 30, 30)
                .addComponent(primaryButton, javax.swing.GroupLayout.PREFERRED_SIZE, 101, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 52, Short.MAX_VALUE)
                .addComponent(cancelButton, javax.swing.GroupLayout.PREFERRED_SIZE, 101, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(17, 17, 17))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                .addContainerGap(22, Short.MAX_VALUE)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(primaryButton)
                    .addComponent(cancelButton))
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void primaryButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_primaryButtonActionPerformed
        
        this.formResult = true;
        this.setVisible(false);
    }//GEN-LAST:event_primaryButtonActionPerformed

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        this.formResult = false;
        this.setVisible(false);
    }//GEN-LAST:event_cancelButtonActionPerformed

    private void targetTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_targetTextFieldFocusLost
        String target = this.targetTextField.getText().trim(); // gets chosen target name
        try { 
            rule.setTarget(target); // sets rule target
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Invalid target name");
            this.targetTextField.setText("");   //  clears target text field
        }
    }//GEN-LAST:event_targetTextFieldFocusLost

    private void sourceIpTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_sourceIpTextFieldFocusLost
        String ip = this.sourceIpTextField.getText().trim();    // gets chosen ip
        try { 
            rule.setSourceIp(ip); // sets rule source ip
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Invalid IPv4 address");
            this.sourceIpTextField.setText("");   //  clears target text field
        }
    }//GEN-LAST:event_sourceIpTextFieldFocusLost

    private void sourcePortTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_sourcePortTextFieldFocusLost

        try { 
            int port = Integer.parseInt(this.sourcePortTextField.getText().trim()); // gets and converts chosen port to integer
            rule.setSourcePort(port); // sets rule source port
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Invalid port");
            this.sourcePortTextField.setText("0");   //  clears source port text field
        }
    }//GEN-LAST:event_sourcePortTextFieldFocusLost

    private void protocolTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_protocolTextFieldFocusLost
        String protocol = this.protocolTextField.getText();     // gets chosen protocol
        try { 
            rule.setProtocol(protocol); // sets rule protocol
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Invalid protocol name");
            this.protocolTextField.setText("");   //  clears protocol text field
        }
    }//GEN-LAST:event_protocolTextFieldFocusLost

    private void destinationIpTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_destinationIpTextFieldFocusLost
         String ip = this.destinationIpTextField.getText().trim();    // gets chosen ip
        try { 
            rule.setDestinationIp(ip); // sets rule source ip
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Invalid IPv4 address");
            this.destinationIpTextField.setText("");   //  clears target text field
        }
    }//GEN-LAST:event_destinationIpTextFieldFocusLost

    private void destinationPortTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_destinationPortTextFieldFocusLost
        try { 
            int port = Integer.parseInt(this.destinationPortTextField.getText().trim()); // gets and converts chosen port to integer
            rule.setDestinationPort(port); // sets rule source port
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Invalid port");
            this.destinationPortTextField.setText("0");   //  clears source port text field
        }
    }//GEN-LAST:event_destinationPortTextFieldFocusLost

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(ConfigureRuleDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ConfigureRuleDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ConfigureRuleDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ConfigureRuleDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the dialog */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                ConfigureRuleDialog dialog = new ConfigureRuleDialog(null, true,null,"INPUT");
                dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                    @Override
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        System.exit(0);
                    }
                });
                dialog.setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cancelButton;
    private javax.swing.JLabel chainLabel;
    private javax.swing.JTextField destinationIpTextField;
    private javax.swing.JTextField destinationPortTextField;
    private javax.swing.JLabel dportlabel;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JButton primaryButton;
    private javax.swing.JTextField protocolTextField;
    private javax.swing.JTextField sourceIpTextField;
    private javax.swing.JTextField sourcePortTextField;
    private javax.swing.JTextField targetTextField;
    // End of variables declaration//GEN-END:variables
}
