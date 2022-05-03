package cn.zcn.authorization.server.grant;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.OAuth2Error;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import cn.zcn.authorization.server.utils.OAuth2Utils;
import org.springframework.util.StringUtils;

import java.security.NoSuchAlgorithmException;
import java.util.Map;

/**
 * 用于处理授权码模式中的令牌颁发请求
 * 参考规范：https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
 */
public class AuthorizationCodeTokenGranter extends BaseTokenGranter {

    private final ServerConfig serverConfig;
    private final AuthorizationCodeService authorizationCodeService;

    public AuthorizationCodeTokenGranter(ServerConfig serverConfig, AuthorizationCodeService authorizationCodeService, TokenService tokenService) {
        super(OAuth2Constants.GRANT_TYPE.AUTHORIZATION_CODE, tokenService);
        this.serverConfig = serverConfig;
        this.authorizationCodeService = authorizationCodeService;
    }

    @Override
    protected AccessToken doGrant(Client client, TokenRequest tokenRequest) throws OAuth2Exception {
        Map<String, String> parameters = tokenRequest.getRequestParameters();
        String authorizationCode = parameters.get(OAuth2Constants.FIELD.CODE);
        String redirectUri = parameters.get(OAuth2Constants.FIELD.REDIRECT_URI);

        if (authorizationCode == null) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, "An authorization code must be supplied.");
        }

        if (!StringUtils.hasText(redirectUri)) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, "An redirect uri must be supplied.");
        }

        UserApprovalAuthentication userApprovalAuthentication = authorizationCodeService.consumeAuthorizationCode(authorizationCode);
        AuthorizationRequest authorizationRequest = userApprovalAuthentication.getAuthorizationRequest();

        if (!client.getClientId().equals(authorizationRequest.getClientId())) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, "Mismatch client id.");
        }

        if (!redirectUri.equals(authorizationRequest.getRedirectUri())) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, "Mismatch redirect uri.");
        }

        validatePKCEParameter(tokenRequest, authorizationRequest);

        tokenRequest.setAuthorizationRequest(authorizationRequest);
        OAuth2Authentication authentication = new OAuth2Authentication(tokenRequest, userApprovalAuthentication.getUserAuthentication());

        return tokenService.issueTokenBoundUser(client, authentication);
    }

    /**
     * 处理 PKCE，参考规范 https://datatracker.ietf.org/doc/html/rfc7636
     *
     * @param tokenRequest         令牌请求
     * @param authorizationRequest 授权请求
     * @throws OAuth2Exception PKCE 参数校验异常
     */
    private void validatePKCEParameter(TokenRequest tokenRequest, AuthorizationRequest authorizationRequest) throws OAuth2Exception {
        String codeChallenge = authorizationRequest.getStringParameter(OAuth2Constants.PKCE.CODE_CHALLENGE);
        String codeVerifier = tokenRequest.getRequestParameters().get(OAuth2Constants.PKCE.CODE_VERIFIER);

        /*
         * 判断是否必须使用 PKCE
         */
        if (serverConfig.isPkceRequried()) {
            if (!StringUtils.hasText(codeChallenge)) {
                throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, "A code_challenge must be supplied in authorization code grant type.");
            }

            if (!StringUtils.hasText(codeVerifier)) {
                throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, "A code_verifier must be supplied in authorization code grant type.");
            }
        }

        if (StringUtils.hasText(codeChallenge)) {
            String pkceMethod = authorizationRequest.getStringParameter(OAuth2Constants.PKCE.CODE_CHALLENGE_METHOD);
            if (!StringUtils.hasText(pkceMethod)) {
                pkceMethod = OAuth2Constants.PKCE.PLAIN;
            }

            /*
             * 判断是否必须使用 S256
             */
            if (serverConfig.isPkceS256Required() && pkceMethod.equals(OAuth2Constants.PKCE.PLAIN)) {
                throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, "Code challenge method must be S256.");
            }

            if (!StringUtils.hasText(codeVerifier)) {
                throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, "Missing code_verifier parameter.");
            }

            try {
                String expectedCodeChallenge = OAuth2Utils.createCodeChallenge(pkceMethod, codeVerifier);
                if (!codeChallenge.equals(expectedCodeChallenge)) {
                    throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, "Mismatch between code_verifier and code_challenge.");
                }
            } catch (NoSuchAlgorithmException e) {
                throw OAuth2Exception.make(OAuth2Error.INVALID_GRANT, e.getMessage(), e);
            }
        }
    }
}
