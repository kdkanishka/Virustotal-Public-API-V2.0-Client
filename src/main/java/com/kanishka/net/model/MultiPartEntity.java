/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.net.model;

import org.apache.http.entity.mime.content.ContentBody;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class MultiPartEntity {

    private String partName;
    private ContentBody entity;

    public MultiPartEntity() {
    }

    public MultiPartEntity(String partName, ContentBody entity) {
        this.partName = partName;
        this.entity = entity;
    }

    public String getPartName() {
        return partName;
    }

    public void setPartName(String partName) {
        this.partName = partName;
    }

    public ContentBody getEntity() {
        return entity;
    }

    public void setEntity(ContentBody entity) {
        this.entity = entity;
    }
}
