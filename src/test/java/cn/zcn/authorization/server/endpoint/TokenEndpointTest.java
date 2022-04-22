package cn.zcn.authorization.server.endpoint;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import cn.zcn.authorization.server.grant.TokenGranter;
import cn.zcn.authorization.server.utils.OAuth2Utils;
import com.google.common.collect.Sets;
import com.sun.security.auth.UserPrincipal;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TokenEndpointTest {

    private TestingClient client;
    private ClientService clientService;
    private TokenRequest tokenRequest;
    private TokenGranter tokenGranter;
    private RequestResolver requestResolver;
    private Map<String, String> requestParameters;
    private TokenEndpoint tokenEndpoint;

    @BeforeEach
    public void beforeEach() {
        client = new TestingClient();
        client.setClientId("client");
        client.setClientSecret("secret");
        client.setScope(Sets.newHashSet("scope1", "scope2"));
        client.setGrantTypes(Sets.newHashSet("authorization_code", "implicit"));
        client.setResponseType(Sets.newHashSet("code", "token"));
        client.setRedirectUris(Sets.newHashSet("client.com/callback"));

        requestParameters = new HashMap<String, String>() {{
            put(OAuth2Constants.FIELD.CLIENT_ID, "client");
            put(OAuth2Constants.FIELD.RESPONSE_TYPE, "code");
            put(OAuth2Constants.FIELD.REDIRECT_URI, "client.com/callback");
            put(OAuth2Constants.FIELD.SCOPE, "scope1");
            put(OAuth2Constants.FIELD.STATE, "state1");
        }};

        tokenRequest = Mockito.spy(new TokenRequest(
                "client",
                Sets.newHashSet("scope1", "scope2"),
                OAuth2Constants.GRANT_TYPE.AUTHORIZATION_CODE,
                requestParameters
        ));

        clientService = Mockito.mock(ClientService.class);
        tokenGranter = Mockito.mock(TokenGranter.class);
        requestResolver = Mockito.mock(RequestResolver.class);

        tokenEndpoint = Mockito.spy(new TokenEndpoint());
        tokenEndpoint.setTokenGranter(tokenGranter);
        tokenEndpoint.setRequestResolver(requestResolver);
        tokenEndpoint.setClientService(clientService);

        Mockito.when(clientService.loadClientByClientId(client.getClientId())).thenReturn(client);
        Mockito.when(requestResolver.resolve2TokenRequest(requestParameters, client)).thenReturn(tokenRequest);
    }

    @Test
    public void testTokenWithInvalidAuthentication() {
        Assertions.assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(() -> tokenEndpoint.token(new UserPrincipal("foo"), requestParameters));


        Assertions.assertThatExceptionOfType(AuthenticationException.class)
                .isThrownBy(() -> tokenEndpoint.token(new TestingAuthenticationToken("foo", "bar"), requestParameters));
    }

    @Test
    public void testTokenWithInvalidClient() {
        Authentication clientAuth = new TestingAuthenticationToken("fff", "dd");
        clientAuth.setAuthenticated(true);

        Mockito.when(clientService.loadClientByClientId(clientAuth.getName())).thenThrow(new OAuth2Exception("invalid_client", "Not Found"));

        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> tokenEndpoint.token(clientAuth, requestParameters));
    }

    @Test
    public void testTokenWithEmptyGrantType() {
        Authentication clientAuth = new TestingAuthenticationToken(client.getClientId(), "dd");
        clientAuth.setAuthenticated(true);

        Mockito.when(tokenRequest.getGrantType()).thenReturn(null);
        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> tokenEndpoint.token(clientAuth, requestParameters))
                .withMessage("Missing grant type.");
    }

    @Test
    public void testTokenWithInvalidGrantType() {
        Authentication clientAuth = new TestingAuthenticationToken(client.getClientId(), "dd");
        clientAuth.setAuthenticated(true);

        Mockito.when(tokenRequest.getGrantType()).thenReturn("ff");
        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> tokenEndpoint.token(clientAuth, requestParameters))
                .withMessageStartingWith("Unsupported grant type :");
    }

    @Test
    public void testTokenMismatchClient() {
        Authentication clientAuth = new TestingAuthenticationToken(client.getClientId(), "dd");
        clientAuth.setAuthenticated(true);

        Mockito.when(tokenRequest.getClientId()).thenReturn("ff");

        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> tokenEndpoint.token(clientAuth, requestParameters))
                .withMessage("Mismatch between authenticated client id and requested client id.");
    }

    @Test
    public void testTokenWithInvalidScope() {
        Authentication clientAuth = new TestingAuthenticationToken(client.getClientId(), "dd");
        clientAuth.setAuthenticated(true);

        Mockito.when(tokenRequest.getScope()).thenReturn(Sets.newHashSet("invalid_scope"));

        Assertions.assertThatExceptionOfType(OAuth2Exception.class)
                .isThrownBy(() -> tokenEndpoint.token(clientAuth, requestParameters))
                .withMessage("Mismatch between requested scopes and client scopes.");
    }

    @Test
    public void testTokenThenSuccess() {
        Authentication clientAuth = new TestingAuthenticationToken(client.getClientId(), "dd");
        clientAuth.setAuthenticated(true);

        TestingAccessToken accessToken = new TestingAccessToken();
        accessToken.setClientId("client");
        accessToken.setTokenType(TokenType.Bearer);
        accessToken.setScope(Sets.newHashSet("a", "b"));
        accessToken.setExpiration(Date.from(Instant.now().plusSeconds(100)));
        accessToken.setCreatedAt(new Date());
        accessToken.setValue("abc123efg");
        Mockito.when(tokenGranter.grant(client, tokenRequest)).thenReturn(accessToken);

        ResponseEntity<Map<String, Object>> rsp = tokenEndpoint.token(clientAuth, requestParameters);
        Map<String, Object> body = rsp.getBody();

        Assertions.assertThat(rsp).isNotNull();
        Assertions.assertThat(rsp.getStatusCode().value()).isEqualTo(200);

        Assertions.assertThat(body).isNotNull();
        Assertions.assertThat(body.size()).isGreaterThan(0);
        Assertions.assertThat(body.get(OAuth2Constants.FIELD.CLIENT_ID)).isEqualTo(accessToken.getClientId());
        Assertions.assertThat(body.get(OAuth2Constants.FIELD.TOKEN_TYPE)).isEqualTo(accessToken.getTokenType().name());
        Assertions.assertThat(body.get(OAuth2Constants.FIELD.SCOPE)).isEqualTo(OAuth2Utils.joinParameterString(accessToken.getScope()));
        Assertions.assertThat(body.get(OAuth2Constants.FIELD.ACCESS_TOKEN)).isEqualTo(accessToken.getValue());
        Assertions.assertThat(body.get(OAuth2Constants.FIELD.EXPIRES_IN)).isEqualTo(accessToken.getExpiresIn() + "");
    }
}
