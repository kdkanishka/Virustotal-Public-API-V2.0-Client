/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotalv2;

import java.net.HttpURLConnection;

/**
 * Wraps HTTP status codes usign Virustotal specific constants
 *
 * @author kdesilva
 */
public final class VirustotalStatus {

    private VirustotalStatus() {
    }
    public static final int FORBIDDEN = HttpURLConnection.HTTP_FORBIDDEN;
    public static final int API_LIMIT_EXCEEDED = HttpURLConnection.HTTP_NO_CONTENT;
    public static final int SUCCESSFUL = HttpURLConnection.HTTP_OK;
}
