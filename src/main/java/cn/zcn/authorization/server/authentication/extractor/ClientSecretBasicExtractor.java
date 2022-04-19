package cn.zcn.authorization.server.authentication.extractor;

import cn.zcn.authorization.server.OAuth2Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Base64;

/**
 * 抽取客户端使用 HTTP Basic authentication 方式传递的客户端的客户端凭证
 */
public class ClientSecretBasicExtractor implements AuthenticationExtractor {

    private final static String BASIC = "basic ";
    private final static String credentialsCharset = "UTF-8";

    private final static Logger logger = LoggerFactory.getLogger(ClientSecretBasicExtractor.class);

    @Override
    public Authentication extract(HttpServletRequest request) throws AuthenticationException {
        String basicAuthorization = request.getHeader(OAuth2Constants.FIELD.AUTHORIZATION);

        String clientId;
        String clientSecret;

        try {
            String[] tokens = extractAndDecodeHeader(basicAuthorization);

            clientId = tokens[0];
            clientSecret = tokens[1];

            logger.debug("Basic Authentication Authorization header found '" + clientId + "'");
        } catch (IOException e) {
            throw new BadCredentialsException("Invalid http basic authorization", e);
        }

        return new UsernamePasswordAuthenticationToken(clientId, clientSecret);
    }

    /**
     * 抽取 http header authorization 中的 client id、client secret
     *
     * @param authorization http header authorization
     * @return 字符串数组，array[0] = client id，array[1] = client secret
     * @throws AuthenticationException      客户端凭证不合法
     * @throws UnsupportedEncodingException Base64 解码 authorization 失败
     */
    private String[] extractAndDecodeHeader(String authorization) throws AuthenticationException, UnsupportedEncodingException {
        byte[] base64Token = authorization.substring(BASIC.length()).getBytes(credentialsCharset);
        byte[] decoded;

        try {
            decoded = Base64.getDecoder().decode(base64Token);
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Failed to decode basic authentication token");
        }

        String token = new String(decoded, credentialsCharset);

        int delim = token.indexOf(":");

        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }

        return new String[]{token.substring(0, delim), token.substring(delim + 1)};
    }

    @Override
    public RequestMatcher getRequestMatcher() {
        return new ClientSecretBasicRequestMatcher();
    }

    private static class ClientSecretBasicRequestMatcher implements RequestMatcher {

        @Override
        public boolean matches(HttpServletRequest request) {
            String basicAuthorization = request.getHeader(OAuth2Constants.FIELD.AUTHORIZATION);

            return basicAuthorization != null && basicAuthorization.toLowerCase().startsWith(BASIC);
        }
    }
}
