/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package utils;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author xceeded
 */
public class RestrictableTableModel extends DefaultTableModel{
        /**
         * Pair of 2 integers. 2D coordinate.
         */
        public class CellCoor extends AbstractMap.SimpleImmutableEntry<Integer,Integer>{
            public CellCoor(int row, int col){
                super(row,col);
                restricteds = new ArrayList<CellCoor>(); // initializes list of readonly cells
            }
        }
        /**
         * List of read-only cells.
         * {@code true} means editable and likewise.
         */
        protected List<CellCoor> restricteds;
        /**
         * If all cells readonly.
         */
        protected boolean isTableReadonly;
        
        public RestrictableTableModel(Object[][] data, Object[] headers){
            super(data,headers);
        }
        
        /**
         * Adds a cell to be in readonly list.
         * @param row
         * @param col
         * @throws Exception If cell already restricted
         */
        public void setCellReadonly(int row, int col) throws Exception{
            isTableReadonly = false;
            CellCoor coor = new CellCoor(row,col);
            if(restricteds.contains(coor))
                throw new Exception("Cell already restricted");
            restricteds.add(coor);
        }
        public void setCellEditable(int row, int col){
            isTableReadonly = false;
            CellCoor coor = new CellCoor(row,col);
            if(restricteds.contains(coor))
                restricteds.remove(coor);
        }
        public void setTableReadonly(){
            isTableReadonly = true;
        }
        public void setTableEditable(){
            restricteds.clear();
            isTableReadonly = false;
        }
        
        @Override
        public boolean isCellEditable(int row, int col){
            CellCoor coor = new CellCoor(row,col);
            return !(isTableReadonly || restricteds.contains(coor));
        }
    } 
