package cn.zcn.authorization.server.endpoint;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.OAuth2Error;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import cn.zcn.authorization.server.grant.TokenGranter;
import cn.zcn.authorization.server.utils.OAuth2Utils;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class AuthorizationEndpoint {

    private ClientService clientService;

    private TokenGranter tokenGranter;

    private RequestResolver requestResolver;

    private ApprovalService approvalService;

    private AuthorizationCodeService authorizationCodeService;

    @RequestMapping(value = ServerConfig.AUTHORIZATION_ENDPOINT, method = RequestMethod.GET)
    public ModelAndView authorize(@RequestParam Map<String, String> parameters, Principal principal) {
        if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
            throw new InsufficientAuthenticationException("No login user!");
        }

        AuthorizationRequest authorizationRequest = requestResolver.resolve2AuthorizationRequest(parameters);
        Client client = clientService.loadClientByClientId(authorizationRequest.getClientId());

        //validate redirect uri
        validateRedirectUri(authorizationRequest.getRedirectUri(), client.getRedirectUris());

        //validate scope
        Set<String> requestedScope = authorizationRequest.getScope();
        Set<String> clientScope = authorizationRequest.getScope();
        for (String scope : requestedScope) {
            if (!clientScope.contains(scope)) {
                throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Mismatch between requested scopes and client scopes.");
            }
        }

        //check supported response type
        String responseType = OAuth2Utils.joinParameterString(authorizationRequest.getResponseType());
        if (!client.getResponseTypes().contains(responseType)) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Unsupported response type : " + responseType);
        }

        // check approve
        boolean isApproved = approvalService.isAllScopeApproved((Authentication) principal, authorizationRequest);
        authorizationRequest.setApproved(isApproved);

        if (isApproved) {
            if (authorizationRequest.getResponseType().contains(OAuth2Constants.FIELD.CODE)) {
                //check supported grant type
                if (!client.getGrantTypes().contains(OAuth2Constants.GRANT_TYPE.AUTHORIZATION_CODE)) {
                    throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Unsupported grant type : authorization_code");
                }

                //issue authorization code
                return new ModelAndView(issueAuthorizationCode((Authentication) principal, authorizationRequest));
            } else if (authorizationRequest.getResponseType().contains(OAuth2Constants.FIELD.TOKEN)) {
                //check supported grant type
                if (!client.getGrantTypes().contains(OAuth2Constants.GRANT_TYPE.IMPLICIT)) {
                    throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Unsupported grant type : implicit");
                }

                // issue access token
                return new ModelAndView(issueAccessToken(client, authorizationRequest));
            }
        }

        return approvalService.redirectForUserApproval(client, authorizationRequest);
    }

    @RequestMapping(value = ServerConfig.AUTHORIZATION_ENDPOINT, method = RequestMethod.POST, params = OAuth2Constants.FIELD.USER_OAUTH_APPROVAL)
    public View approveOrDeny(@RequestParam Map<String, String> approvalParameters, HttpServletRequest request, Principal principal) {
        if (!(principal instanceof Authentication) || !((Authentication) principal).isAuthenticated()) {
            throw new InsufficientAuthenticationException("No login user!");
        }

        AuthorizationRequest authorizationRequest = approvalService.loadAuthorizationRequestAfterApproveOrDeny(request, approvalParameters);
        if (authorizationRequest == null) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_REQUEST, "Cannot approve uninitialized authorization request.");
        }

        boolean approved = approvalService.updateApproveOrDeny((Authentication) principal, authorizationRequest, approvalParameters);

        if (!approved) {
            String redirectUri = buildErrorRedirectUrl(authorizationRequest, OAuth2Error.createException(OAuth2Error.ACCESS_DENIED, "User denied access"));
            return new RedirectView(redirectUri, false, true, false);
        }

        if (authorizationRequest.getResponseType().contains(OAuth2Constants.FIELD.CODE)) {
            //issue authorization code
            return issueAuthorizationCode((Authentication) principal, authorizationRequest);
        }

        //issue access token
        Client client = clientService.loadClientByClientId(authorizationRequest.getClientId());
        return issueAccessToken(client, authorizationRequest);
    }

    /**
     * issue authorization code
     *
     * @param authentication       user authorization
     * @param authorizationRequest authorization request
     * @return redirect view
     */
    private View issueAuthorizationCode(Authentication authentication, AuthorizationRequest authorizationRequest) {
        try {
            String code = authorizationCodeService.createAuthorizationCode(new OAuth2PreviousAuthentication(authorizationRequest, authentication));

            Map<String, String> response = new HashMap<>();
            response.put(OAuth2Constants.FIELD.CODE, code);

            return new RedirectView(buildSuccessfulRedirectUrl(authorizationRequest, response, false), false, true, false);
        } catch (OAuth2Exception e) {
            return new RedirectView(buildErrorRedirectUrl(authorizationRequest, e), false, true, false);
        }
    }

    /**
     * issue access token
     *
     * @param client               client
     * @param authorizationRequest authorization request
     * @return redirect view
     */
    private View issueAccessToken(Client client, AuthorizationRequest authorizationRequest) {
        try {
            TokenRequest tokenRequest = new TokenRequest(authorizationRequest.getClientId(), authorizationRequest.getScope(), "implicit", authorizationRequest.getRequestParameters());
            tokenRequest.setAuthorizationRequest(authorizationRequest);

            AccessToken accessToken = tokenGranter.grant(client, tokenRequest);
            if (accessToken == null) {
                throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Unsupported grant type : implicit.");
            }

            Map<String, String> response = new HashMap<>();
            response.put(OAuth2Constants.FIELD.ACCESS_TOKEN, accessToken.getValue());
            response.put(OAuth2Constants.FIELD.TOKEN_TYPE, accessToken.getTokenType().name());

            if (accessToken.getExpiration() != null) {
                response.put(OAuth2Constants.FIELD.EXPIRES_IN, String.valueOf(accessToken.getExpiresIn()));
            }

            if (!accessToken.getScope().isEmpty()) {
                response.put(OAuth2Constants.FIELD.SCOPE, OAuth2Utils.joinParameterString(accessToken.getScope()));
            }

            return new RedirectView(buildSuccessfulRedirectUrl(authorizationRequest, response, true), false, true, false);
        } catch (OAuth2Exception e) {
            return new RedirectView(buildErrorRedirectUrl(authorizationRequest, e), false, true, false);
        }
    }

    private String buildSuccessfulRedirectUrl(AuthorizationRequest authorizationRequest, Map<String, String> parameters, boolean isFragment) {
        String state = authorizationRequest.getRequestParameters().get(OAuth2Constants.FIELD.STATE);
        if (StringUtils.hasText(state)) {
            parameters.put(OAuth2Constants.FIELD.STATE, state);
        }

        return OAuth2Utils.appendRedirectUri(authorizationRequest.getRedirectUri(), parameters, isFragment);
    }

    private String buildErrorRedirectUrl(AuthorizationRequest authorizationRequest, OAuth2Exception e) {
        Map<String, String> parameters = new HashMap<>();
        String state = authorizationRequest.getRequestParameters().get(OAuth2Constants.FIELD.STATE);

        if (StringUtils.hasText(e.getErrorCode())) {
            parameters.put(OAuth2Constants.ERROR.ERROR, e.getErrorCode());
        }

        if (StringUtils.hasText(e.getErrorDescription())) {
            parameters.put(OAuth2Constants.ERROR.ERROR_DESCRIPTION, e.getErrorDescription());
        }

        if (StringUtils.hasText(state)) {
            parameters.put(OAuth2Constants.FIELD.STATE, state);
        }

        if (StringUtils.hasText(e.getErrorUri())) {
            parameters.put(OAuth2Constants.ERROR.ERROR_URI, e.getErrorUri());
        }

        return OAuth2Utils.appendRedirectUri(authorizationRequest.getRedirectUri(), parameters, false);
    }

    /**
     * 校验授权请求中 redirect uri 参数，是否与客户端已注册的 redirect uris 中的一个匹配
     * 注意客户端 redirect uris 可能是已编码的格式。
     *
     * @param requestedRedirectUri 授权请求中 redirect uri
     * @param clientRegisterUris   客户端注册的 redirect uris
     * @throws OAuth2Exception 授权请求中 redirect uri 参数与客户端注册的 redirect uris 都不匹配
     */
    private void validateRedirectUri(String requestedRedirectUri, Set<String> clientRegisterUris) throws OAuth2Exception {
        if (clientRegisterUris.isEmpty()) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "clientRegisteredUri is empty!");
        }

        if (!StringUtils.hasText(requestedRedirectUri)) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Missing redirect uri!");
        }

        int i = 0;
        for (String uri : clientRegisterUris) {
            if (OAuth2Utils.urlMatches(requestedRedirectUri, uri)) {
                break;
            }
            i++;
        }

        if (i == clientRegisterUris.size()) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Mismatch between requestedRedirectUri and clientRegisterUris");
        }
    }

    public void setRequestResolver(RequestResolver requestResolver) {
        this.requestResolver = requestResolver;
    }

    public void setClientService(ClientService clientService) {
        this.clientService = clientService;
    }

    public void setAuthorizationCodeService(AuthorizationCodeService authorizationCodeService) {
        this.authorizationCodeService = authorizationCodeService;
    }

    public void setApprovalService(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    public void setTokenGranter(TokenGranter tokenGranter) {
        this.tokenGranter = tokenGranter;
    }
}
