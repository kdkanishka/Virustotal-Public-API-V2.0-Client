/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package httpbin;

import java.util.HashMap;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class HttpBinResponse {

    private String url;
    private HashMap<String, String> args;
    private String origin;
    private HashMap<String, String> headers;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public HashMap<String, String> getArgs() {
        return args;
    }

    public void setArgs(HashMap<String, String> args) {
        this.args = args;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public HashMap<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(HashMap<String, String> headers) {
        this.headers = headers;
    }
}
