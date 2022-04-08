package cn.zcn.authorization.server.authentication.extractor;

import cn.zcn.authorization.server.OAuth2Constants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ClientSecretBasicExtractorTest {

    private HttpServletRequest request;

    @BeforeEach
    public void beforeEach() {
        request = Mockito.mock(HttpServletRequest.class);
    }

    @Test
    public void testExtractWhenSuccess() {
        String data = encode("client", "123", ":");
        Mockito.when(request.getHeader(OAuth2Constants.AUTHORIZATION)).thenReturn("basic " + data);

        ClientSecretBasicExtractor extractor = new ClientSecretBasicExtractor();
        Authentication auth = extractor.extract(request);

        Assertions.assertNotNull(auth);
        Assertions.assertEquals("client", auth.getName());
        Assertions.assertEquals("client", auth.getPrincipal());
        Assertions.assertEquals("123", auth.getCredentials());
    }

    @Test
    public void testExtractUsingInvalidAuthentication() {
        Mockito.when(request.getHeader(OAuth2Constants.AUTHORIZATION)).thenReturn("iii*iii");

        ClientSecretBasicExtractor extractor = new ClientSecretBasicExtractor();
        Assertions.assertThrows(BadCredentialsException.class, () -> extractor.extract(request));
    }

    @Test
    public void testExtractUsingInvalidAuthentication2() {
        String data = encode("client", "123", "|");
        Mockito.when(request.getHeader(OAuth2Constants.AUTHORIZATION)).thenReturn(data);

        ClientSecretBasicExtractor extractor = new ClientSecretBasicExtractor();
        Assertions.assertThrows(BadCredentialsException.class, () -> extractor.extract(request));
    }

    @Test
    public void testRequestMatcherWhenMatched() {
        ClientSecretBasicExtractor extractor = new ClientSecretBasicExtractor();
        RequestMatcher requestMatcher = extractor.getRequestMatcher();

        String data = encode("client", "123", ":");
        Mockito.when(request.getHeader(OAuth2Constants.AUTHORIZATION)).thenReturn("basic " + data);

        Assertions.assertTrue(requestMatcher.matches(request));
    }

    @Test
    public void testRequestMatcherWhenUnmatched() {
        ClientSecretBasicExtractor extractor = new ClientSecretBasicExtractor();
        RequestMatcher requestMatcher = extractor.getRequestMatcher();

        Mockito.when(request.getHeader(OAuth2Constants.AUTHORIZATION)).thenReturn(null);
        Assertions.assertFalse(requestMatcher.matches(request));

        Mockito.when(request.getHeader(OAuth2Constants.AUTHORIZATION)).thenReturn("");
        Assertions.assertFalse(requestMatcher.matches(request));
        
        Mockito.when(request.getHeader(OAuth2Constants.AUTHORIZATION)).thenReturn("basic 123");
        Assertions.assertTrue(requestMatcher.matches(request));

        Mockito.when(request.getHeader(OAuth2Constants.AUTHORIZATION)).thenReturn("123");
        Assertions.assertFalse(requestMatcher.matches(request));
    }

    private String encode(String clientId, String clientSecret, String delim) {
        return Base64.getEncoder().encodeToString((clientId + delim + clientSecret).getBytes(StandardCharsets.UTF_8));
    }
}
