package cn.zcn.authorization.server.grant;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * 处理 Implicit flow 中的令牌颁发
 * 参考规范：https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.1
 */
public class ImplicitTokenGranter extends BaseTokenGranter {

    public ImplicitTokenGranter(TokenService tokenService) {
        super("implicit", tokenService);
    }

    @Override
    protected AccessToken doGrant(Client client, TokenRequest tokenRequest) throws OAuth2Exception {
        Authentication userAuthentication = SecurityContextHolder.getContext().getAuthentication();
        if (userAuthentication == null || !userAuthentication.isAuthenticated()) {
            throw new InsufficientAuthenticationException("No user authentication present.");
        }

        return tokenService.issueTokenWithClient(client, new OAuth2Authentication(tokenRequest, userAuthentication));
    }
}

