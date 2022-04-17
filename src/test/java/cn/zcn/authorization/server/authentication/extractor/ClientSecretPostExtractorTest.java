package cn.zcn.authorization.server.authentication.extractor;

import cn.zcn.authorization.server.OAuth2Constants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

public class ClientSecretPostExtractorTest {

    private HttpServletRequest request;

    @BeforeEach
    public void beforeEach() {
        request = Mockito.mock(HttpServletRequest.class);
    }

    @Test
    public void testExtractWhenSuccess() {
        Mockito.when(request.getParameter(OAuth2Constants.FIELD.CLIENT_ID)).thenReturn("client");
        Mockito.when(request.getParameter(OAuth2Constants.FIELD.CLIENT_SECRET)).thenReturn("123");

        ClientSecretPostExtractor extractor = new ClientSecretPostExtractor();
        Authentication auth = extractor.extract(request);

        Assertions.assertNotNull(auth);
        Assertions.assertEquals("client", auth.getName());
        Assertions.assertEquals("client", auth.getPrincipal());
        Assertions.assertEquals("123", auth.getCredentials());
    }

    @Test
    public void testExtractUsingEmptyClientSecret() {
        Mockito.when(request.getParameter(OAuth2Constants.FIELD.CLIENT_ID)).thenReturn("client");
        Mockito.when(request.getParameter(OAuth2Constants.FIELD.CLIENT_SECRET)).thenReturn(null);

        ClientSecretPostExtractor extractor = new ClientSecretPostExtractor();
        Authentication auth = extractor.extract(request);

        Assertions.assertNotNull(auth);
        Assertions.assertEquals("client", auth.getName());
        Assertions.assertEquals("client", auth.getPrincipal());
        Assertions.assertEquals("", auth.getCredentials());
    }

    @Test
    public void testRequestMatcherWhenMatched() {
        Mockito.when(request.getParameter(OAuth2Constants.FIELD.CLIENT_ID)).thenReturn("client");

        ClientSecretPostExtractor extractor = new ClientSecretPostExtractor();
        RequestMatcher requestMatcher = extractor.getRequestMatcher();

        Assertions.assertTrue(requestMatcher.matches(request));
    }

    @Test
    public void testRequestMatcherWhenUnmatched() {
        ClientSecretPostExtractor extractor = new ClientSecretPostExtractor();
        RequestMatcher requestMatcher = extractor.getRequestMatcher();

        Assertions.assertFalse(requestMatcher.matches(request));
    }
}
