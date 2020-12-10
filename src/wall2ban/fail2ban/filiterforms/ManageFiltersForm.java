/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban.fail2ban.filiterforms;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import javax.swing.DefaultListModel;
import javax.swing.JOptionPane;
import wall2ban.ConfirmForm;
import wall2ban.fail2ban.Filter;
import wall2ban.fail2ban.FilterStore;

/**
 *
 * @author ADMIN
 */
public class ManageFiltersForm extends javax.swing.JFrame {
    
    private FilterStore filterStore;
    
    /**
     * Creates new form ManageFiltersForm
     */
    public ManageFiltersForm(FilterStore filterStore) {
        initComponents();
        this.filterStore = filterStore;
        bindFiltersList();  // shows data to view
    }

    /**
     * Creates new filter names list and sets it to list model.
     */
    private void bindFiltersList(){
        List<String> actionNames = new ArrayList<String>();
        for(Filter filter : filterStore.readAll())
            actionNames.add(filter.getName());
        Comparator c = new Comparator<String>(){
            @Override
            public int compare(String a, String b){return a.compareTo(b);}
        };
        actionNames.sort(c);
        DefaultListModel<String> model = new DefaultListModel<String>();
        model.addAll(actionNames);
        this.filtersJList.setModel(model);
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
        jLabel2 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        filtersJList = new javax.swing.JList<>();
        jLabel1 = new javax.swing.JLabel();
        editButton = new javax.swing.JButton();
        createButton = new javax.swing.JButton();
        deleteButton = new javax.swing.JButton();
        jScrollPane3 = new javax.swing.JScrollPane();
        definitionTextArea = new javax.swing.JTextArea();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        jLabel2.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel2.setText("Definition");
        jLabel2.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        filtersJList.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        filtersJList.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                filtersJListMouseClicked(evt);
            }
        });
        jScrollPane1.setViewportView(filtersJList);

        jLabel1.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel1.setText("Filters");
        jLabel1.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        editButton.setText("Edit");
        editButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editButtonActionPerformed(evt);
            }
        });

        createButton.setText("Create Filter");
        createButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                createButtonActionPerformed(evt);
            }
        });

        deleteButton.setText("Delete Filter");
        deleteButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteButtonActionPerformed(evt);
            }
        });

        definitionTextArea.setEditable(false);
        definitionTextArea.setColumns(20);
        definitionTextArea.setRows(5);
        jScrollPane3.setViewportView(definitionTextArea);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, 113, Short.MAX_VALUE)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(editButton, javax.swing.GroupLayout.PREFERRED_SIZE, 103, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 47, Short.MAX_VALUE)
                        .addComponent(createButton)
                        .addGap(32, 32, 32)
                        .addComponent(deleteButton))
                    .addComponent(jScrollPane3)
                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(26, 26, 26)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 29, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 238, Short.MAX_VALUE)
                    .addComponent(jScrollPane3))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(editButton)
                    .addComponent(createButton)
                    .addComponent(deleteButton))
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void editButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editButtonActionPerformed
        if(this.filtersJList.getSelectedIndex()>=0){    // checks if user clicked a valid item
            String actionName = this.filtersJList.getSelectedValue();   // gets selected action name
            Filter action = filterStore.readByKey(actionName);  // gets action from list
            ConfigureFilterDialog form = new ConfigureFilterDialog(this,true,action); // creates new config form to edit action
            form.setLocationRelativeTo(this);  // sets dialog center to this form
            form.setVisible(true);
            if(form.getFormResult()){   // checks if operation succeeded
                Filter newFilter = form.getFilter(); // gets updated action
                try {
                    filterStore.update(newFilter);  // updates action
                    bindFiltersList();      // updates actions list in view
                } catch (Exception err) {
                    JOptionPane.showMessageDialog(this, "Failed to update action.\nError: "+err.getMessage());
                }
                
            }
        }
    }//GEN-LAST:event_editButtonActionPerformed

    private void createButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_createButtonActionPerformed
        if(this.filtersJList.getSelectedIndex()>=0){    // checks if user clicked a valid item
            ConfigureFilterDialog form = new ConfigureFilterDialog(this,true,null); // creates new config form to edit action
            form.setLocationRelativeTo(this);  // sets dialog center to this form
            form.setVisible(true);
            if(form.getFormResult()){   // checks if operation succeeded
                Filter newFilter = form.getFilter(); // gets updated action
                try {
                    filterStore.create(newFilter);  // updates action
                    bindFiltersList();      // updates actions list in view
                } catch (Exception err) {
                    JOptionPane.showMessageDialog(this, "Failed to update action.\nError: "+err.getMessage());
                }
                
            }
        }
    }//GEN-LAST:event_createButtonActionPerformed

    private void deleteButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteButtonActionPerformed
      if(this.filtersJList.getSelectedIndex()>=0){    // checks if user clicked a valid item
            String filterName = this.filtersJList.getSelectedValue();   // gets selected filter name
            Filter filter = filterStore.readByKey(filterName);  // gets filter from list
            
            ConfirmForm delForm = new ConfirmForm(this,true);
            delForm.setLocationRelativeTo(this);  // sets dialog center to this form
            delForm.setMessage("Delete filter "+filter.getName()+ "?");
            delForm.setVisible(true);
            if(delForm.getFormResult()){    // checks if operation succeeded
                try {
                    filterStore.delete(filter); // deletes filter
                    bindFiltersList();      // updates filters list in view
                } catch (Exception err) {
                   JOptionPane.showMessageDialog(this, "Failed to delete filter.\nError: "+err.getMessage());
                }
            }
        }
      
    }//GEN-LAST:event_deleteButtonActionPerformed

    private void filtersJListMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_filtersJListMouseClicked
        int index = this.filtersJList.getSelectedIndex();
        if(index>=0){   // checks if user selected a valid item
            String filterName = this.filtersJList.getSelectedValue();
            Filter filter = filterStore.readByKey(filterName);    // gets filter in list
            this.definitionTextArea.setText(filter.toConfigString()); // sets config string for text area
            
        }
    }//GEN-LAST:event_filtersJListMouseClicked

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
            java.util.logging.Logger.getLogger(ManageFiltersForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(ManageFiltersForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(ManageFiltersForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(ManageFiltersForm.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                FilterStore fstore = new FilterStore();
                new ManageFiltersForm(fstore).setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton createButton;
    private javax.swing.JTextArea definitionTextArea;
    private javax.swing.JButton deleteButton;
    private javax.swing.JButton editButton;
    private javax.swing.JList<String> filtersJList;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane3;
    // End of variables declaration//GEN-END:variables
}
