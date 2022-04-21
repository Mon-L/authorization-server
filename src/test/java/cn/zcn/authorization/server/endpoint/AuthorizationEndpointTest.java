package cn.zcn.authorization.server.endpoint;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import cn.zcn.authorization.server.grant.TokenGranter;
import com.google.common.collect.Sets;
import com.sun.security.auth.UserPrincipal;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class AuthorizationEndpointTest {

    private TestingClient client;
    private Authentication authentication;
    private Map<String, String> requestParameters;
    private AuthorizationRequest authorizationRequest;

    private ClientService clientService;
    private TokenGranter tokenGranter;
    private RequestResolver requestResolver;
    private ApprovalService approvalService;
    private AuthorizationCodeService authorizationCodeService;

    private AuthorizationEndpoint authorizationEndpoint;

    @BeforeEach
    public void beforeEach() {
        client = new TestingClient();
        client.setClientId("client");
        client.setClientSecret("secret");
        client.setScope(Sets.newHashSet("scope1", "scope2"));
        client.setGrantTypes(Sets.newHashSet("authorization_code", "implicit"));
        client.setResponseType(Sets.newHashSet("code", "token"));
        client.setRedirectUris(Sets.newHashSet("client.com/callback"));

        authentication = new UsernamePasswordAuthenticationToken("a", "b", Collections.emptySet());

        requestParameters = new HashMap<String, String>() {{
            put(OAuth2Constants.FIELD.CLIENT_ID, "client");
            put(OAuth2Constants.FIELD.RESPONSE_TYPE, "code");
            put(OAuth2Constants.FIELD.REDIRECT_URI, "client.com/callback");
            put(OAuth2Constants.FIELD.SCOPE, "scope1");
            put(OAuth2Constants.FIELD.STATE, "state1");
        }};

        authorizationRequest = Mockito.spy(new AuthorizationRequest(
                "client",
                Sets.newHashSet("scope1", "scope2"),
                Sets.newHashSet("code"),
                "client.com/callback",
                requestParameters,
                false
        ));

        clientService = Mockito.mock(ClientService.class);
        tokenGranter = Mockito.mock(TokenGranter.class);
        requestResolver = Mockito.mock(RequestResolver.class);
        approvalService = Mockito.mock(ApprovalService.class);
        authorizationCodeService = Mockito.mock(AuthorizationCodeService.class);

        Mockito.when(clientService.loadClientByClientId(client.getClientId())).thenReturn(client);
        Mockito.when(requestResolver.resolve2AuthorizationRequest(requestParameters)).thenReturn(authorizationRequest);

        authorizationEndpoint = new AuthorizationEndpoint();
        authorizationEndpoint.setClientService(clientService);
        authorizationEndpoint.setTokenGranter(tokenGranter);
        authorizationEndpoint.setRequestResolver(requestResolver);
        authorizationEndpoint.setApprovalService(approvalService);
        authorizationEndpoint.setAuthorizationCodeService(authorizationCodeService);
    }

    @Test
    public void testAuthorizeWithAnonymous() {
        Assertions.assertThatExceptionOfType(InsufficientAuthenticationException.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(Collections.emptyMap(), null));

        Assertions.assertThatExceptionOfType(InsufficientAuthenticationException.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(Collections.emptyMap(), new UserPrincipal("foo")));

        Assertions.assertThatExceptionOfType(InsufficientAuthenticationException.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(Collections.emptyMap(), new TestingAuthenticationToken("foo", "bar")));
    }

    @Test
    public void testAuthorizeWithInvalidClient() {
        Mockito.when(clientService.loadClientByClientId(Mockito.any())).thenThrow(new OAuth2Exception("invalid_client", "not found"));

        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(requestParameters, authentication))
                .withMessage("not found");
    }

    @Test
    public void testAuthorizeWithInvalidRedirectUri() {
        client.setRedirectUris(null);
        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(requestParameters, authentication))
                .withMessage("clientRegisteredUri is empty!");

        client.setRedirectUris(Collections.emptySet());
        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(requestParameters, authentication))
                .withMessage("clientRegisteredUri is empty!");

        authorizationRequest.setRedirectUri(null);
        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(requestParameters, authentication))
                .withMessage("Missing redirect uri!");
    }

    @Test
    public void testAuthorizeMismatchRedirectUri() {
        authorizationRequest.setRedirectUri("xxx.com/callback");
        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(requestParameters, authentication))
                .withMessage("Mismatch between requestedRedirectUri and clientRegisterUris.");
    }

    @Test
    public void testAuthorizeInvalidScope() {
        authorizationRequest.setScope(Sets.newHashSet("scope1", "invalid_scope"));
        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(requestParameters, authentication))
                .withMessage("Mismatch between requested scopes and client scopes.");
    }

    @Test
    public void testAuthorizeInvalidResponseType() {
        client.setResponseType(Collections.emptySet());
        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(requestParameters, authentication))
                .withMessage("Unsupported response type : code");
    }

    @Test
    public void testAuthorizeNoApproval() {
        authorizationEndpoint.authorize(requestParameters, authentication);
        Mockito.verify(approvalService, Mockito.times(1)).redirectForUserApproval(client, authorizationRequest);
    }

    @Test
    public void testAuthorizeUnsupportedGrantType() {
        client.setGrantTypes(Collections.emptySet());
        Mockito.when(approvalService.isAlreadyApproved(authentication, authorizationRequest)).thenReturn(true);

        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(requestParameters, authentication))
                .withMessage("Unsupported grant type : authorization_code.");

        Mockito.when(authorizationRequest.getResponseType()).thenReturn(Sets.newHashSet("token"));
        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> authorizationEndpoint.authorize(requestParameters, authentication))
                .withMessage("Unsupported grant type : implicit.");
    }

    @Test
    public void testAuthorizeThenIssueAuthorizationCode() {
        Mockito.when(approvalService.isAlreadyApproved(authentication, authorizationRequest)).thenReturn(true);
        Mockito.when(authorizationCodeService.createAuthorizationCode(Mockito.any())).thenReturn("xxx");

        ModelAndView modelAndView = authorizationEndpoint.authorize(requestParameters, authentication);
        Assertions.assertThat(modelAndView).isNotNull();

        View view = modelAndView.getView();
        Assertions.assertThat(view).isNotNull();

        Assertions.assertThat(view).isExactlyInstanceOf(RedirectView.class);
        RedirectView redirectView = (RedirectView) view;

        Assertions.assertThat(redirectView.getUrl()).isEqualTo("client.com/callback?code=xxx&state=state1");
    }

    @Test
    public void testAuthorizeThenIssueToken() {
        TestingAccessToken accessToken = new TestingAccessToken();
        accessToken.setClientId("client");
        accessToken.setTokenType(TokenType.Bearer);
        accessToken.setScope(Sets.newHashSet("a", "b"));
        accessToken.setExpiration(Date.from(Instant.now().plusSeconds(100)));
        accessToken.setCreatedAt(new Date());
        accessToken.setValue("abc123efg");

        Mockito.when(authorizationRequest.getResponseType()).thenReturn(Sets.newHashSet("token"));
        Mockito.when(approvalService.isAlreadyApproved(authentication, authorizationRequest)).thenReturn(true);
        Mockito.when(tokenGranter.grant(Mockito.any(), Mockito.any())).thenReturn(accessToken);

        ModelAndView modelAndView = authorizationEndpoint.authorize(requestParameters, authentication);
        Assertions.assertThat(modelAndView).isNotNull();

        View view = modelAndView.getView();
        Assertions.assertThat(view).isNotNull();
        Assertions.assertThat(view).isExactlyInstanceOf(RedirectView.class);

        RedirectView redirectView = (RedirectView) view;
        Assertions.assertThat(redirectView.getUrl()).isEqualTo("client.com/callback#client_id=client&access_token=abc123efg&token_type=Bearer&expires_in=99&scope=a%20b&state=state1");
    }
}
