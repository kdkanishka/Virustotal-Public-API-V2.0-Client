/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.exception;

import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;
import org.junit.Test;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class APIKeyNotFoundExceptionTest {
    
    public APIKeyNotFoundExceptionTest() {
    }


    @Test(expected = APIKeyNotFoundException.class)
    public void testException() throws APIKeyNotFoundException {
        //without setting api key
        VirustotalPublicV2 virusTotalv2API=new VirustotalPublicV2Impl();
    }
    
    @Test(expected = APIKeyNotFoundException.class)
    public void testExceptionForEmptyKey() throws APIKeyNotFoundException {
        //without setting api key
        VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalv2API=new VirustotalPublicV2Impl();
    }
}