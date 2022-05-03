package cn.zcn.authorization.server.exception;

import cn.zcn.authorization.server.OAuth2Constants;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.json.GsonHttpMessageConverter;
import org.springframework.http.converter.json.JsonbHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 默认的 Exception 处理类
 */
public class DefaultExceptionWriter implements ExceptionWriter {

    private static final boolean jackson2Present;
    private static final boolean gsonPresent;
    private static final boolean jsonbPresent;

    static {
        ClassLoader classLoader = DefaultExceptionWriter.class.getClassLoader();

        jackson2Present = ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper", classLoader)
                && ClassUtils.isPresent("com.fasterxml.jackson.core.JsonGenerator", classLoader);

        gsonPresent = ClassUtils.isPresent("com.google.gson.Gson", classLoader);

        jsonbPresent = ClassUtils.isPresent("javax.json.bind.Jsonb", classLoader);
    }

    private static GenericHttpMessageConverter<Object> getDelegatingHttpMessageConverter() {
        if (jackson2Present) {
            return new MappingJackson2HttpMessageConverter();
        }

        if (gsonPresent) {
            return new GsonHttpMessageConverter();
        }

        if (jsonbPresent) {
            return new JsonbHttpMessageConverter();
        }

        throw new IllegalStateException("HttpMessageConverter must not be null.");
    }

    private final ThrowableAnalyzer throwableAnalyzer = new ThrowableAnalyzer();
    private final GenericHttpMessageConverter<Object> httpMessageConverter = getDelegatingHttpMessageConverter();
    private final Converter<OAuth2Exception, Map<String, String>> exceptionConverter = new DefaultExceptionConverter();

    @Override
    public void write(Exception exception, ServletWebRequest webRequest) throws IOException {
        if (exception == null || webRequest.getNativeResponse() == null) {
            return;
        }

        OAuth2Exception target = convert2OAuth2Exception(exception);

        ServerHttpResponse outputMessage = new ServletServerHttpResponse((HttpServletResponse) webRequest.getNativeResponse());
        outputMessage.setStatusCode(target.getHttpStatus());

        // add default headers
        outputMessage.getHeaders().set("Cache-Control", "no-store");
        outputMessage.getHeaders().set("Pragma", "no-cache");
        outputMessage.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, String> output = exceptionConverter.convert(target);
        httpMessageConverter.write(output, MediaType.APPLICATION_JSON, outputMessage);
    }

    private OAuth2Exception convert2OAuth2Exception(Exception source) {
        Throwable[] causeChain = throwableAnalyzer.determineCauseChain(source);
        Throwable cause = throwableAnalyzer.getFirstThrowableOfType(OAuth2Exception.class, causeChain);

        if (cause != null) {
            return (OAuth2Exception) cause;
        }

        cause = throwableAnalyzer.getFirstThrowableOfType(AuthenticationException.class, causeChain);
        if (cause != null) {
            return OAuth2Exception.make(OAuth2Error.UNAUTHORIZED, cause.getMessage(), source);
        }

        cause = throwableAnalyzer.getFirstThrowableOfType(AccessDeniedException.class, causeChain);
        if (cause != null) {
            return OAuth2Exception.make(OAuth2Error.ACCESS_DENIED, cause.getMessage(), source);
        }

        return OAuth2Exception.make(OAuth2Error.SERVER_ERROR, source.getMessage(), source);
    }

    private static class DefaultExceptionConverter implements Converter<OAuth2Exception, Map<String, String>> {

        @Override
        public Map<String, String> convert(OAuth2Exception e) {
            Map<String, String> ret = new LinkedHashMap<>();
            if (StringUtils.hasText(e.getErrorCode())) {
                ret.put(OAuth2Constants.ERROR.ERROR, e.getErrorCode());
            }

            if (StringUtils.hasText(e.getMessage())) {
                ret.put(OAuth2Constants.ERROR.ERROR_DESCRIPTION, e.getErrorDescription());
            }

            if (StringUtils.hasText(e.getErrorUri())) {
                ret.put(OAuth2Constants.ERROR.ERROR_URI, e.getErrorUri());
            }

            return ret;
        }
    }
}
