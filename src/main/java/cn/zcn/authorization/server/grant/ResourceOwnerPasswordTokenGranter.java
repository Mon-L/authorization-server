package cn.zcn.authorization.server.grant;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.OAuth2Error;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.StringUtils;

/**
 * 处理密码模式中的令牌颁发
 * 参考规范：https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2
 */
public class ResourceOwnerPasswordTokenGranter extends BaseTokenGranter {

    /**
     * 用户客户端授权的
     */
    private final AuthenticationManager authenticationManager;

    public ResourceOwnerPasswordTokenGranter(TokenService tokenService, AuthenticationManager authenticationManager) {
        super(OAuth2Constants.GRANT_TYPE.PASSWORD, tokenService);
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected AccessToken doGrant(Client client, TokenRequest tokenRequest) throws OAuth2Exception {
        String username = tokenRequest.getRequestParameters().get("username");
        String password = tokenRequest.getRequestParameters().get("password");

        if (!StringUtils.hasText(username) || !StringUtils.hasText(password)) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, "Username and password must be supplied.");
        }

        tokenRequest.getRequestParameters().remove("password");

        Authentication userAuth = new UsernamePasswordAuthenticationToken(username, password);
        ((AbstractAuthenticationToken) userAuth).setDetails(tokenRequest.getRequestParameters());

        try {
            userAuth = authenticationManager.authenticate(userAuth);
        } catch (AuthenticationException e) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, e.getMessage());
        }

        if (userAuth == null || !userAuth.isAuthenticated()) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, "Mismatch between username and password.");
        }

        return tokenService.issueTokenBoundUser(client, new OAuth2Authentication(tokenRequest, userAuth));
    }
}
