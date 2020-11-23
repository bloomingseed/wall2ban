/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package wall2ban;

import java.util.List;

/**
 * Interface for DA objects
 * @param <E> Entity's type
 * @param <K> Primary key field's type
 * @author xceeded
 */
public interface IStore<E,K> {   
    /**
     * Used to retrieve list of all entities
     * @return List of all entities type {@link E}
     */
    List<E> readAll();
    E readByKey(K key);
    void create(E entity) throws Exception;
    void update(E entity) throws Exception;
    void delete(E entity) throws Exception;
    
}
