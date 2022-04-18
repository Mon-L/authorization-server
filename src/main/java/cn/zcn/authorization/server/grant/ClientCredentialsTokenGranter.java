package cn.zcn.authorization.server.grant;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * 处理客户端模式的令牌颁发流程
 * 参考规范：https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2
 */
public class ClientCredentialsTokenGranter extends BaseTokenGranter {

    public ClientCredentialsTokenGranter(TokenService tokenService) {
        super(OAuth2Constants.GRANT_TYPE.CLIENT_CREDENTIALS, tokenService);
    }

    @Override
    protected AccessToken doGrant(Client client, TokenRequest tokenRequest) throws OAuth2Exception {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new InsufficientAuthenticationException("No client authentication present.");
        }

        return tokenService.issueTokenBoundClient(client, new OAuth2Authentication(tokenRequest, authentication));
    }
}
