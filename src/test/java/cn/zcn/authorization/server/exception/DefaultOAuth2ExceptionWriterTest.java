package cn.zcn.authorization.server.exception;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.context.request.ServletWebRequest;

import java.io.IOException;

public class DefaultOAuth2ExceptionWriterTest {

    private OAuth2ExceptionWriter oAuth2ExceptionWriter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    public void beforeEach() {
        this.oAuth2ExceptionWriter = Mockito.spy(new DefaultOAuth2ExceptionWriter());
        this.request = new MockHttpServletRequest();
        this.response = new MockHttpServletResponse();
    }

    @AfterEach
    public void checkHttpHeaders() {
        Assertions.assertEquals(response.getHeaderValue("Cache-Control"), "no-store");
        Assertions.assertEquals(response.getHeaderValue("Pragma"), "no-cache");
    }

    @Test
    public void testWriteUsingException() throws IOException {
        Exception exception = new Exception("foo");

        oAuth2ExceptionWriter.write(exception, new ServletWebRequest(request, response));

        JsonNode node = toJson(response.getContentAsByteArray());

        Assertions.assertEquals(OAuth2Error.SERVER_ERROR.getErrorCode(), node.get("error").asText());
        Assertions.assertEquals(exception.getMessage(), node.get("error_description").asText());
        Assertions.assertNull(node.get("error_uri"));

    }

    @Test
    public void testWriteUsingRuntimeException() throws IOException {
        RuntimeException exception = new RuntimeException("foo");

        oAuth2ExceptionWriter.write(exception, new ServletWebRequest(request, response));

        JsonNode node = toJson(response.getContentAsByteArray());

        Assertions.assertEquals(OAuth2Error.SERVER_ERROR.getErrorCode(), node.get("error").asText());
        Assertions.assertEquals(exception.getMessage(), node.get("error_description").asText());
        Assertions.assertNull(node.get("error_uri"));
    }

    @Test
    public void testWriteUsingAuthenticationException() throws IOException {
        BadCredentialsException exception = new BadCredentialsException("foo");

        oAuth2ExceptionWriter.write(exception, new ServletWebRequest(request, response));

        JsonNode node = toJson(response.getContentAsByteArray());

        Assertions.assertEquals(OAuth2Error.UNAUTHORIZED.getErrorCode(), node.get("error").asText());
        Assertions.assertEquals(exception.getMessage(), node.get("error_description").asText());
        Assertions.assertNull(node.get("error_uri"));
    }

    @Test
    public void testWriteUsingAccessDeniedException() throws IOException {
        AccessDeniedException exception = new AccessDeniedException("foo");

        oAuth2ExceptionWriter.write(exception, new ServletWebRequest(request, response));

        JsonNode node = toJson(response.getContentAsByteArray());

        Assertions.assertEquals(OAuth2Error.ACCESS_DENIED.getErrorCode(), node.get("error").asText());
        Assertions.assertEquals(exception.getMessage(), node.get("error_description").asText());
        Assertions.assertNull(node.get("error_uri"));
    }

    @Test
    public void testWriteUsingOAuth2Exception() throws IOException {
        OAuth2Exception exception = new OAuth2Exception("foo", "bar");

        oAuth2ExceptionWriter.write(exception, new ServletWebRequest(request, response));

        JsonNode node = toJson(response.getContentAsByteArray());

        Assertions.assertEquals("foo", node.get("error").asText());
        Assertions.assertEquals(exception.getMessage(), node.get("error_description").asText());
        Assertions.assertNull(node.get("error_uri"));
    }

    @Test
    public void testWriteWithErrorUri() throws IOException {
        OAuth2Exception exception = new OAuth2Exception("foo", "bar");
        exception.errorUri("url");

        oAuth2ExceptionWriter.write(exception, new ServletWebRequest(request, response));

        JsonNode node = toJson(response.getContentAsByteArray());

        Assertions.assertEquals("foo", node.get("error").asText());
        Assertions.assertEquals(exception.getMessage(), node.get("error_description").asText());
        Assertions.assertEquals(exception.getErrorUri(), node.get("error_uri").asText());
    }

    private JsonNode toJson(byte[] content) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readTree(content);
    }
}
