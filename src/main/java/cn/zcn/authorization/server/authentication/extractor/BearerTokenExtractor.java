package cn.zcn.authorization.server.authentication.extractor;

import cn.zcn.authorization.server.OAuth2Constants;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

/**
 * 抽取请求头中的 Bearer Token
 */
public class BearerTokenExtractor implements AuthenticationExtractor {

    private final static String BEARER_PREFIX = "bearer ";

    @Override
    public Authentication extract(HttpServletRequest request) throws AuthenticationException {
        String token = getBearerToken(request);
        if (token != null) {
            return new PreAuthenticatedAuthenticationToken(token, "");
        }

        return null;
    }

    private String getBearerToken(HttpServletRequest request) {
        Enumeration<String> headers = request.getHeaders(OAuth2Constants.FIELD.AUTHORIZATION);
        while (headers.hasMoreElements()) {
            String header = headers.nextElement().toLowerCase().trim();

            if (header.startsWith(BEARER_PREFIX)) {
                String token = header.substring(BEARER_PREFIX.length());
                int comma = token.indexOf(',');
                if (comma > 0) {
                    token = token.substring(0, comma);
                }

                return token;
            }
        }

        return null;
    }

    @Override
    public RequestMatcher getRequestMatcher() {
        return AnyRequestMatcher.INSTANCE;
    }
}
