package cn.zcn.authorization.server.authentication.extractor;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;

public class BearerTokenExtractorTest {

    private AuthenticationExtractor extractor;
    private MockHttpServletRequest request;

    @BeforeEach
    public void beforeEach() {
        extractor = new BearerTokenExtractor();
        request = new MockHttpServletRequest();
    }

    @Test
    public void testExtractWithoutToken() {
        Assertions.assertNull(extractor.extract(request));
    }

    @Test
    public void testExtractWithOneBearerToken() {
        request.addHeader("Authorization", "Bearer 8989");

        Authentication authentication = extractor.extract(request);
        Assertions.assertNotNull(authentication);
        Assertions.assertEquals("8989", authentication.getName());
    }

    @Test
    public void testExtractWithMultiAuthorization() {
        request.addHeader("Authorization", "aaaa");
        request.addHeader("Authorization", "Bearer 8989");
        request.addHeader("Authorization", "bbbb");

        Authentication authentication = extractor.extract(request);
        Assertions.assertNotNull(authentication);
        Assertions.assertEquals("8989", authentication.getName());
    }
}
