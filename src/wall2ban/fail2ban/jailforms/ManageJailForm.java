/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.fail2ban.jailforms;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.JOptionPane;
import wall2ban.ConfirmForm;
import wall2ban.fail2ban.DefaultJailConfig;
import wall2ban.fail2ban.Jail;
import wall2ban.fail2ban.JailStore;

/**
 *
 * @author Admin
 */
public class ManageJailForm extends javax.swing.JFrame {

    private JailStore jailStore;
    

    /**
     * Creates new form ManageJailForm2
     */
    public ManageJailForm(JailStore jailStore) {
        super();
        initComponents();
        this.jailStore = jailStore;
        
        bindDefaults();
        bindJailsList();
        
    }
    
    /**
     * Shows default configs to view.
     */
    private void bindDefaults(){
        Map<String,String> defaults = jailStore.getDefaultJailConfig().get("DEFAULT");
        this.ignoreIpTextField.setText(defaults.get("ignoreip"));
        this.banTimeTextField.setText(defaults.get("bantime"));
        this.findTimeTextField.setText(defaults.get("findtime"));
        this.maxRetryTextField.setText(defaults.get("maxretry"));
    }
    private void bindJailsList(){
        List<String> jailNames = new ArrayList<String>();
        for(Jail jail : jailStore.readAll())
            jailNames.add(jail.getName());
        Comparator c = new Comparator<String>(){
            @Override
            public int compare(String a, String b){return a.compareTo(b);}
        };
        jailNames.sort(c);  // sorts jail names ascending
        DefaultListModel<String> model = new DefaultListModel<String>();
        model.addAll(jailNames);    // adds all names to model
        this.jailsJList.setModel(model);
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        editButton = new javax.swing.JButton();
        maxRetryTextField = new javax.swing.JTextField();
        createButton = new javax.swing.JButton();
        advancedButton = new javax.swing.JButton();
        deleteButton = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jLabel7 = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        ignoreIpTextField = new javax.swing.JTextField();
        banTimeTextField = new javax.swing.JTextField();
        jScrollPane5 = new javax.swing.JScrollPane();
        jailsJList = new javax.swing.JList<>();
        jScrollPane1 = new javax.swing.JScrollPane();
        definitionTextArea = new javax.swing.JTextArea();
        findTimeTextField = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        editButton.setText("Edit");
        editButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editButtonActionPerformed(evt);
            }
        });

        maxRetryTextField.setText(" ");
        maxRetryTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                maxRetryTextFieldFocusLost(evt);
            }
        });

        createButton.setText("Create Jail");
        createButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                createButtonActionPerformed(evt);
            }
        });

        advancedButton.setText("Advanced");
        advancedButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                advancedButtonActionPerformed(evt);
            }
        });

        deleteButton.setText("Delete Jail");
        deleteButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteButtonActionPerformed(evt);
            }
        });

        jLabel3.setText("Default Values");

        jLabel4.setText("Ignore IP:");

        jLabel2.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel2.setText("Definition");
        jLabel2.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        jLabel5.setText("Ban Time:");

        jLabel6.setText("Find Time:");

        jLabel7.setText("Max retries");

        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("Jails");
        jLabel1.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        ignoreIpTextField.setText(" ");
        ignoreIpTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                ignoreIpTextFieldFocusLost(evt);
            }
        });

        banTimeTextField.setText(" ");
        banTimeTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                banTimeTextFieldFocusLost(evt);
            }
        });

        jailsJList.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        jailsJList.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jailsJListMouseClicked(evt);
            }
        });
        jScrollPane5.setViewportView(jailsJList);

        definitionTextArea.setEditable(false);
        definitionTextArea.setColumns(20);
        definitionTextArea.setRows(5);
        jScrollPane1.setViewportView(definitionTextArea);

        findTimeTextField.setText(" ");
        findTimeTextField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusLost(java.awt.event.FocusEvent evt) {
                findTimeTextFieldFocusLost(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jLabel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jLabel4, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, 113, Short.MAX_VALUE)
                            .addComponent(jLabel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(6, 6, 6)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(ignoreIpTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(banTimeTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(advancedButton, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addGroup(layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(findTimeTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE))))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(jLabel7, javax.swing.GroupLayout.DEFAULT_SIZE, 113, Short.MAX_VALUE)
                                .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 113, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(6, 6, 6)
                                .addComponent(maxRetryTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 132, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(jScrollPane1)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(editButton, javax.swing.GroupLayout.PREFERRED_SIZE, 103, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(23, 23, 23)
                                        .addComponent(createButton)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 30, Short.MAX_VALUE)
                                        .addComponent(deleteButton, javax.swing.GroupLayout.PREFERRED_SIZE, 118, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(advancedButton, javax.swing.GroupLayout.PREFERRED_SIZE, 28, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(10, 10, 10)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(ignoreIpTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 32, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(banTimeTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 32, Short.MAX_VALUE))
                .addGap(13, 13, 13)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(findTimeTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 34, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(maxRetryTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 30, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(19, 19, 19)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 29, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 203, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(editButton)
                            .addComponent(createButton)
                            .addComponent(deleteButton)))
                    .addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 233, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents
  
    private void editButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editButtonActionPerformed
        if(this.jailsJList.getSelectedIndex()>=0){    // checks if user clicked a valid item
            String jailName = this.jailsJList.getSelectedValue();   // gets selected jail name
            Jail jail = jailStore.readByKey(jailName);  // gets jail from list
            ConfigureJailDialog form = new ConfigureJailDialog(this,true,jail); // creates new config form to edit jail
            form.setLocationRelativeTo(this);  // sets dialog center to this form
            form.setVisible(true);  // shows form and waits
            if(form.getFormResult()){   // checks if operation succeeded
                Jail newJail = form.getJail(); // gets updated jail
                try {
                    jailStore.update(newJail);  // updates jail
                    bindJailsList();      // updates jails list in view
                } catch (Exception err) {
                    JOptionPane.showMessageDialog(this, "Failed to update jail.\nError: "+err.getMessage());
                }
                
            }
        }
    }//GEN-LAST:event_editButtonActionPerformed

    private void createButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_createButtonActionPerformed
        if(this.jailsJList.getSelectedIndex()>=0){    // checks if user clicked a valid item
            ConfigureJailDialog form = new ConfigureJailDialog(this,true,null); // creates new config form to edit jail
            form.setLocationRelativeTo(this);  // sets dialog center to this form
            form.setVisible(true);  // shows form and waits
            if(form.getFormResult()){   // checks if operation succeeded
                Jail newJail = form.getJail(); // gets new jail
                try {
                    jailStore.create(newJail);  // updates jail
                    bindJailsList();      // updates jails list in view
                } catch (Exception err) {
                    JOptionPane.showMessageDialog(this, "Failed to create jail.\nError: "+err.getMessage());
                }
                
            }
        }
    }//GEN-LAST:event_createButtonActionPerformed

    private void advancedButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_advancedButtonActionPerformed
        AdvancedJailDialog adJailForm = new AdvancedJailDialog(this, true, this.jailStore.getDefaultJailConfig().toConfigString());
        adJailForm.setLocationRelativeTo(this);  // sets dialog center to this form
        adJailForm.setVisible(true);    // shows form
        if(adJailForm.getFormResult()){ // checks if operation succeeded
            String newConfig = adJailForm.getConfigString();
            this.jailStore.setDefaultJailConfig(DefaultJailConfig.parseDefaultJailConfig(newConfig));
            bindDefaults(); // updates default values to view.
        }
    }//GEN-LAST:event_advancedButtonActionPerformed

    private void deleteButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteButtonActionPerformed
      ConfirmForm delJailForm = new ConfirmForm(this, true);
      int index=jailsJList.getSelectedIndex();
      if(index<0) 
              return;
      String jailName = jailsJList.getSelectedValue();  // gets selected jail's name
      delJailForm.setLocationRelativeTo(this);  // sets dialog center to this form
      delJailForm.setMessage("Delete jail "+jailName+" ?");
      delJailForm.setVisible(true); // shows form and waits
      boolean res = delJailForm.getFormResult();    // gets result
      if(res){  // checks if delete button clicked
          Jail jail = this.jailStore.readByKey(jailName); // gets selected jail
          try {
              jailStore.delete(jail);   // deletes jail
              bindJailsList();    // updates jails list
          } catch (Exception err) {
              JOptionPane.showMessageDialog(this, "Failed to delete jail.\nError: "+err.getMessage());
          }
      }
    }//GEN-LAST:event_deleteButtonActionPerformed

    /**
     * Handles adds or replaces default value in Default section of the
     * Default Jail Config.
     * @param key
     * @param value 
     */
    private void updateField(String key, String value){
        Map<String,String> defaults = this.jailStore.getDefaultJailConfig().get("DEFAULTS");    // gets section default's properties map
        if(defaults.containsKey(key))
           defaults.replace(key, value);    // replaces ban jail content
       else
           defaults.put(key, value);   // adds this key and value
        updateProps();
    }
    /**
     * Updates some default properties to view.
     */
    private void updateProps(){
        Map<String,String> map = this.jailStore.getDefaultJailConfig().get("DEFAULTS");    // gets section default's properties map
        this.ignoreIpTextField.setText(map.get("ignoreip"));
        this.banTimeTextField.setText(map.get("bantime"));
        this.findTimeTextField.setText(map.get("findtime"));
        this.maxRetryTextField.setText(map.get("maxretry"));
        updateConfigTextArea();
    }
    /**
     * Updates jail config text area to displays config string of selected jail.
     */
    private void updateConfigTextArea(){
        int index = this.jailsJList.getSelectedIndex();
        if(index>=0){   // checks if user selected a valid item
            String jailName = this.jailsJList.getSelectedValue();
            Jail jail = jailStore.readByKey(jailName);    // gets jail in list
            this.definitionTextArea.setText(jail.toConfigString()); // sets config string for text area
            
        }
    }
    
    private void findTimeTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_findTimeTextFieldFocusLost
        String content = this.ignoreIpTextField.getText();
        updateField("findtime",content);
    }//GEN-LAST:event_findTimeTextFieldFocusLost

    private void ignoreIpTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_ignoreIpTextFieldFocusLost
        String content = this.ignoreIpTextField.getText();
        updateField("ignoreip",content);
    }//GEN-LAST:event_ignoreIpTextFieldFocusLost

    private void banTimeTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_banTimeTextFieldFocusLost
        String content = this.ignoreIpTextField.getText();
        updateField("bantime",content);
    }//GEN-LAST:event_banTimeTextFieldFocusLost

    private void maxRetryTextFieldFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_maxRetryTextFieldFocusLost
        String content = this.ignoreIpTextField.getText();
        updateField("maxretry",content);
    }//GEN-LAST:event_maxRetryTextFieldFocusLost

    private void jailsJListMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jailsJListMouseClicked
        updateConfigTextArea();
    }//GEN-LAST:event_jailsJListMouseClicked

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
            java.util.logging.Logger.getLogger(ManageJailForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ManageJailForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ManageJailForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ManageJailForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the dialog */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    JailStore jstore = new JailStore();
                    ManageJailForm dialog = new ManageJailForm(jstore);
                    dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                        @Override
                        public void windowClosing(java.awt.event.WindowEvent e) {
                            System.exit(0);
                        }
                    });
                    dialog.setLocationRelativeTo(null);
                    dialog.setVisible(true);
                } catch (Exception ex) {
                    Logger.getLogger(ManageJailForm.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton advancedButton;
    private javax.swing.JTextField banTimeTextField;
    private javax.swing.JButton createButton;
    private javax.swing.JTextArea definitionTextArea;
    private javax.swing.JButton deleteButton;
    private javax.swing.JButton editButton;
    private javax.swing.JTextField findTimeTextField;
    private javax.swing.JTextField ignoreIpTextField;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JList<String> jailsJList;
    private javax.swing.JTextField maxRetryTextField;
    // End of variables declaration//GEN-END:variables
}
