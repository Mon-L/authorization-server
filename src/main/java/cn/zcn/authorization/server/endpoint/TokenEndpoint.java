package cn.zcn.authorization.server.endpoint;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.ExceptionWriter;
import cn.zcn.authorization.server.exception.OAuth2Error;
import cn.zcn.authorization.server.grant.TokenGranter;
import cn.zcn.authorization.server.utils.OAuth2Utils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class TokenEndpoint {

    private TokenGranter tokenGranter;
    private ClientService clientService;
    private RequestResolver requestResolver;
    private ExceptionWriter exceptionWriter;

    @RequestMapping(value = ServerConfig.TOKEN_ENDPOINT, method = RequestMethod.POST)
    public ResponseEntity<Map<String, Object>> token(Principal principal, @RequestParam Map<String, String> parameters) {
        if (!(principal instanceof Authentication)) {
            throw new InsufficientAuthenticationException("No client authentication present.");
        }

        String authenticatedClientId = parseClientId(principal);
        Client authenticatedClient = clientService.loadClientByClientId(authenticatedClientId);
        TokenRequest tokenRequest = requestResolver.resolve2TokenRequest(parameters, authenticatedClient);

        if (!StringUtils.hasText(tokenRequest.getGrantType())) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Missing grant type.");
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

        return toResponse(accessToken);
    }

    private ResponseEntity<Map<String, Object>> toResponse(AccessToken accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Cache-Control", "no-store");
        headers.set("Pragma", "no-cache");

        Map<String, Object> rsp = new LinkedHashMap<>();
        rsp.put(OAuth2Constants.FIELD.CLIENT_ID, accessToken.getClientId());
        rsp.put(OAuth2Constants.FIELD.TOKEN_TYPE, accessToken.getTokenType().name());
        rsp.put(OAuth2Constants.FIELD.ACCESS_TOKEN, accessToken.getValue());

        if (!accessToken.getScope().isEmpty()) {
            rsp.put(OAuth2Constants.FIELD.SCOPE, OAuth2Utils.joinParameterString(accessToken.getScope()));
        }

        if (accessToken.getExpiration() != null) {
            rsp.put(OAuth2Constants.FIELD.EXPIRES_IN, String.valueOf(accessToken.getExpiresIn()));
        }

        return new ResponseEntity<>(rsp, headers, HttpStatus.OK);
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

    @ExceptionHandler(Exception.class)
    public void handleException(Exception e, HttpServletRequest request, HttpServletResponse response) throws IOException {
        exceptionWriter.write(e, new ServletWebRequest(request, response));
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

    public void setExceptionWriter(ExceptionWriter exceptionWriter) {
        this.exceptionWriter = exceptionWriter;
    }
}
