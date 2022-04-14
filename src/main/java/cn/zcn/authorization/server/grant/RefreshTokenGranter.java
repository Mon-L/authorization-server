package cn.zcn.authorization.server.grant;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.OAuth2Error;
import org.springframework.util.StringUtils;

/**
 * 处理刷新令牌流程中的令牌刷新
 * 参考规范：https://datatracker.ietf.org/doc/html/rfc6749#section-1.5
 */
public class RefreshTokenGranter extends BaseTokenGranter {

    public RefreshTokenGranter(String supportedGrantType, TokenService tokenService) {
        super(supportedGrantType, tokenService);
    }

    @Override
    public AccessToken doGrant(Client client, TokenRequest tokenRequest) {
        String refreshToken = tokenRequest.getRequestParameters().get("refresh_token");

        if (!StringUtils.hasText(refreshToken)) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "refresh_token must not be null");
        }

        OAuth2Authentication oauth2Authentication = tokenService.loadAuthenticationWithRefreshToken(refreshToken);
        return tokenService.refreshToken(client, oauth2Authentication);
    }
}
