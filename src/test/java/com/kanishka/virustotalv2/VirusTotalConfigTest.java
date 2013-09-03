/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotalv2;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author kdkanishka@gmail.com
 */
public class VirusTotalConfigTest {
    
    public VirusTotalConfigTest() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    /**
     * Test of getConfigInstance method, of class VirusTotalConfig.
     */
    @Test
    public void testGetConfigInstance() {
        System.out.println("Testing GetConfigInstance()");
        VirusTotalConfig instance1 = VirusTotalConfig.getConfigInstance();
        VirusTotalConfig instance2 = VirusTotalConfig.getConfigInstance();
        assertEquals(instance1, instance2);
    }

    /**
     * Test of getVirusTotalAPIKey method, of class VirusTotalConfig.
     */
    @Test
    public void testGetVirusTotalAPIKey() {
        System.out.println("getVirusTotalAPIKey");
        String expResult = "";
        VirusTotalConfig instance=VirusTotalConfig.getConfigInstance();
        String key = instance.getVirusTotalAPIKey();
        assertEquals(expResult, key);
    }

    /**
     * Test of setVirusTotalAPIKey method, of class VirusTotalConfig.
     */
    @Test
    public void testSetVirusTotalAPIKey() {
        System.out.println("setVirusTotalAPIKey");
        String expectedApiKey="testval";
        VirusTotalConfig instance=VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey(expectedApiKey);
        VirusTotalConfig instance2=VirusTotalConfig.getConfigInstance();
        String resultApiKey=instance2.getVirusTotalAPIKey();
        assertEquals(expectedApiKey, resultApiKey);
    }
}