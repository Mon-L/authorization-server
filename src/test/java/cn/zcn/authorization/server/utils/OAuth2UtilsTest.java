package cn.zcn.authorization.server.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

public class OAuth2UtilsTest {

    @Test
    public void testAppendRedirectUriWhenRawUri() {
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("a", "v1");
        parameters.put("b", "v2");
        parameters.put("c", new String[]{"v3", "v4"});
        parameters.put("d", "v5 v6");

        String ret = OAuth2Utils.appendRedirectUri("https://www.example.com/callback p1", parameters, false);
        Assertions.assertEquals("https://www.example.com/callback%20p1?a=v1&b=v2&c=v3,v4&d=v5%20v6", ret);
    }

    @Test
    public void testAppendRedirectUriWithEncodedUri() {
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("a", "v1");
        parameters.put("b", "v2&v3");
        parameters.put("c", new String[]{"v3", "v4"});
        parameters.put("d", "v5 v6");

        String ret = OAuth2Utils.appendRedirectUri("https://www.example.com/%26callback%20p1", parameters, false);
        Assertions.assertEquals("https://www.example.com/%26callback%20p1?a=v1&b=v2%26v3&c=v3,v4&d=v5%20v6", ret);
    }

    @Test
    public void testAppendRedirectUriWithQuery() {
        Map<String, Object> parameters = new LinkedHashMap<>();
        parameters.put("a", "v1");
        parameters.put("b", "v2");
        parameters.put("c", "v3,v4");
        parameters.put("d", "v5 v6");

        String ret = OAuth2Utils.appendRedirectUri("https://www.example.com/callback p1", parameters, true);
        Assertions.assertEquals("https://www.example.com/callback%20p1#a=v1&b=v2&c=v3,v4&d=v5%20v6", ret);
    }

    @Test
    public void testUrlMatch() {
        Assertions.assertTrue(OAuth2Utils.urlMatches(
                "https://www.example.com/url1",
                "https://www.example.com/url1"
        ));

        Assertions.assertFalse(OAuth2Utils.urlMatches(
                "http://www.example.com/url1",
                "https://www.example.com/url1"
        ));

        Assertions.assertFalse(OAuth2Utils.urlMatches(
                "https://www.example.com/url1",
                "https://www.example.com/url2xxxx"
        ));

        Assertions.assertFalse(OAuth2Utils.urlMatches(
                "https://www.example.com:8889/url1",
                "https://www.example.com:8888/url1"
        ));

        Assertions.assertTrue(OAuth2Utils.urlMatches(
                "localhost:8080/url1",
                "localhost:8080/url1"
        ));

        Assertions.assertFalse(OAuth2Utils.urlMatches(
                "localhost:8080/url1",
                "localhost:8080/url1/pdsaf"
        ));

        Assertions.assertTrue(OAuth2Utils.urlMatches(
                "https://www.example.com:8888/url/1",
                "https://www.example.com:8888/url\\1"
        ));

        Assertions.assertTrue(OAuth2Utils.urlMatches(
                "https://www.example.com:8888/url1 v",
                "https://www.example.com:8888/url1%20v"
        ));
    }
}
