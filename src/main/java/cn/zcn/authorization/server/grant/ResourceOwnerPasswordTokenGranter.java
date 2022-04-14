package cn.zcn.authorization.server.grant;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.OAuth2Error;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * 处理密码模式中的令牌颁发
 * 参考规范：https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2
 */
public class ResourceOwnerPasswordTokenGranter extends BaseTokenGranter {

    private final AuthenticationManager authenticationManager;

    public ResourceOwnerPasswordTokenGranter(TokenService tokenService, AuthenticationManager authenticationManager) {
        super("password", tokenService);
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected AccessToken doGrant(Client client, TokenRequest tokenRequest) throws OAuth2Exception {
        String username = tokenRequest.getRequestParameters().get("username");
        String password = tokenRequest.getRequestParameters().get("password");

        tokenRequest.removeRequestParameter("password");

        Authentication userAuth = new UsernamePasswordAuthenticationToken(username, password);
        ((AbstractAuthenticationToken) userAuth).setDetails(tokenRequest.getRequestParameters());

        try {
            userAuth = authenticationManager.authenticate(userAuth);
        } catch (AuthenticationException e) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, e.getMessage());
        }

        if (userAuth == null || !userAuth.isAuthenticated()) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Mismatch username and password.");
        }

        return tokenService.issueTokenWithUser(client, new OAuth2Authentication(tokenRequest, userAuth));
    }
}
