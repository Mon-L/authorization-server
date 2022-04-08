package cn.zcn.authorization.server.authentication.extractor;

import cn.zcn.authorization.server.OAuth2Constants;
import com.google.common.base.Strings;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

/**
 * 抽取客户端使用 HTTP POST 方式传递的客户端的客户端凭证
 */
public class ClientSecretPostExtractor implements AuthenticationExtractor {

    @Override
    public Authentication extract(HttpServletRequest request) throws AuthenticationException {
        String clientId = request.getParameter(OAuth2Constants.CLIENT_ID);
        String clientSecret = request.getParameter(OAuth2Constants.CLIENT_SECRET);

        if (clientSecret == null) {
            clientSecret = "";
        }

        clientId = clientId.trim();

        return new UsernamePasswordAuthenticationToken(clientId, clientSecret);
    }

    @Override
    public RequestMatcher getRequestMatcher() {
        return new ClientSecretPostRequestMatcher();
    }

    private static class ClientSecretPostRequestMatcher implements RequestMatcher {

        @Override
        public boolean matches(HttpServletRequest request) {
            String clientId = request.getParameter(OAuth2Constants.CLIENT_ID);

            return !Strings.isNullOrEmpty(clientId);
        }
    }
}
