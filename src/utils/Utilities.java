/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package utils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Paths;

/**
 *
 * @author xceeded
 */
public class Utilities {
    public static class Utils{
        public static String getWorkingFoler(){
            return System.getProperty("user.dir");
        }
        public static String implode(String[] arr, String sep){
            if(sep==null|| sep.isBlank())
                sep=",";
            StringBuilder b = new StringBuilder();
            int N = arr.length;
            for(int i = 0; i<N; ++i){
                b.append(arr[i]);
                if(i<N-1)
                    b.append(sep);
            }
            return b.toString();
        }
        public static void saveToFile(String path, String content) throws IOException{
            File file = Paths.get(path).toFile();
            BufferedWriter bwriter = new BufferedWriter(new FileWriter(file));
            bwriter.write(content);
            bwriter.close();
        }
    }
          
}
