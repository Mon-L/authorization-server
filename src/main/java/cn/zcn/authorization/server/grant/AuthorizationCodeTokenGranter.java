package cn.zcn.authorization.server.grant;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.OAuth2Error;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * 用于处理授权码模式中的令牌颁发请求
 * 参考规范：https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 */
public class AuthorizationCodeTokenGranter extends BaseTokenGranter {

    private final AuthorizationCodeService authorizationCodeService;

    public AuthorizationCodeTokenGranter(AuthorizationCodeService authorizationCodeService, TokenService tokenService) {
        super(OAuth2Constants.GRANT_TYPE.AUTHORIZATION_CODE, tokenService);
        this.authorizationCodeService = authorizationCodeService;
    }

    @Override
    protected AccessToken doGrant(Client client, TokenRequest tokenRequest) throws OAuth2Exception {
        Map<String, String> parameters = tokenRequest.getRequestParameters();
        String authorizationCode = parameters.get(OAuth2Constants.FIELD.CODE);
        String redirectUri = parameters.get(OAuth2Constants.FIELD.REDIRECT_URI);

        if (authorizationCode == null) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "An authorization code must be supplied.");
        }

        if (!StringUtils.hasText(redirectUri)) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "An redirect uri must be supplied.");
        }

        UserApprovalAuthentication userApprovalAuthentication = authorizationCodeService.consumeAuthorizationCode(authorizationCode);
        AuthorizationRequest authorizationRequest = userApprovalAuthentication.getAuthorizationRequest();

        if (!client.getClientId().equals(authorizationRequest.getClientId())) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Mismatch client id.");
        }

        if (!redirectUri.equals(authorizationRequest.getRedirectUri())) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Mismatch redirect uri.");
        }

        tokenRequest.setAuthorizationRequest(authorizationRequest);
        OAuth2Authentication authentication = new OAuth2Authentication(tokenRequest, userApprovalAuthentication.getUserAuthentication());

        return tokenService.issueTokenBoundUser(client, authentication);
    }
}
