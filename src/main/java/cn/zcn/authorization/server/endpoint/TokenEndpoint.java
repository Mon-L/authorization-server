package cn.zcn.authorization.server.endpoint;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.OAuth2Error;
import cn.zcn.authorization.server.grant.TokenGranter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class TokenEndpoint {

    private TokenGranter tokenGranter;
    private ClientService clientService;
    private RequestResolver requestResolver;

    @RequestMapping(value = ServerConfig.TOKEN_ENDPOINT, method = RequestMethod.POST)
    public ResponseEntity<AccessToken> token(Principal principal, @RequestParam Map<String, String> parameters) {
        if (!(principal instanceof Authentication)) {
            throw new InsufficientAuthenticationException("No client authentication present.");
        }

        String authenticatedClientId = parseClientId(principal);
        Client authenticatedClient = clientService.loadClientByClientId(authenticatedClientId);
        TokenRequest tokenRequest = requestResolver.resolve2TokenRequest(parameters, authenticatedClient);

        if (!StringUtils.hasText(tokenRequest.getGrantType())) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Mismatch grant type.");
        }

        if (!authenticatedClientId.equals(tokenRequest.getClientId())) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Mismatch between authenticated client id and requested client id.");
        }

        if (OAuth2Constants.GRANT_TYPE.AUTHORIZATION_CODE.equals(tokenRequest.getGrantType())) {
            tokenRequest.setScope(Collections.emptySet());
        }

        if (OAuth2Constants.GRANT_TYPE.IMPLICIT.equals(tokenRequest.getGrantType())) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Should not invoke token endpoint when using implicit grant type.");
        }

        //如果请求不含有 scope 参数，将会跳过 scope 校验。如授权码模式或客户端不申请任何权限的情况下。
        if (!tokenRequest.getScope().isEmpty()) {
            Set<String> clientScope = authenticatedClient.getScope();
            for (String scope : tokenRequest.getScope()) {
                if (!clientScope.contains(scope)) {
                    throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Mismatch between requested scopes and client scopes.");
                }
            }
        }

        AccessToken accessToken = tokenGranter.grant(authenticatedClient, tokenRequest);
        if (accessToken == null) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Unsupported grant type : " + tokenRequest.getGrantType());
        }

        HttpHeaders headers = new HttpHeaders();
        headers.set("Cache-Control", "no-store");
        headers.set("Pragma", "no-cache");
        return new ResponseEntity<>(accessToken, headers, HttpStatus.OK);
    }

    private String parseClientId(Principal principal) {
        Authentication client = (Authentication) principal;
        if (!client.isAuthenticated()) {
            throw new InsufficientAuthenticationException("No client authenticated present.");
        }

        if (client instanceof OAuth2Authentication) {
            return ((OAuth2Authentication) client).getTokenRequest().getClientId();
        }

        return client.getName();
    }

    public void setClientService(ClientService clientService) {
        this.clientService = clientService;
    }

    public void setTokenGranter(TokenGranter tokenGranter) {
        this.tokenGranter = tokenGranter;
    }

    public void setRequestResolver(RequestResolver requestResolver) {
        this.requestResolver = requestResolver;
    }
}
