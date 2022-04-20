package cn.zcn.authorization.server.authentication.provider;

import cn.zcn.authorization.server.Client;
import cn.zcn.authorization.server.ClientAuthMethod;
import cn.zcn.authorization.server.ClientService;
import cn.zcn.authorization.server.ServerConfig;
import cn.zcn.authorization.server.authentication.JWTAssertionAuthenticationToken;
import cn.zcn.authorization.server.jose.ClientJOSEService;
import cn.zcn.authorization.server.jose.JWTVerifier;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jwt.*;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import java.util.Date;

public class JWTAssertionAuthenticationProviderTest {

    private static final String ISS = "client";
    private static final String SUB = ISS;
    private static final String AUD = "aud1";
    private static final String JTI = "jti1";
    private static final String TOKEN_PATH = "/token";

    private Client client;
    private ServerConfig serverConfig;
    private ClientService clientService;

    private JWTVerifier jwtVerifier;
    private ClientJOSEService clientJOSEService;
    private JWTAssertionAuthenticationProvider provider;

    private final Date future = Date.from(Instant.now().plusSeconds(10));
    private final Date past = Date.from(Instant.now().minusSeconds(10));

    @BeforeEach
    public void beforeEach() {
        this.serverConfig = new ServerConfig.Builder().issuer(ISS).tokenEndpoint(TOKEN_PATH).build();
        this.client = Mockito.mock(Client.class);
        this.clientService = Mockito.mock(ClientService.class);

        this.jwtVerifier = Mockito.mock(JWTVerifier.class);
        this.clientJOSEService = Mockito.mock(ClientJOSEService.class);
        this.provider = Mockito.spy(new JWTAssertionAuthenticationProvider(serverConfig, clientService, clientJOSEService));

        Mockito.when(clientService.loadClientByClientId(Mockito.anyString())).thenReturn(client);
        Mockito.when(client.getTokenEndpointAuthMethod()).thenReturn(ClientAuthMethod.SECRET_JWT);
        Mockito.when(client.getTokenEndpointAuthSigningAlg()).thenReturn(JWSAlgorithm.HS512);
        Mockito.when(clientJOSEService.getVerifier(Mockito.any(), Mockito.any())).thenReturn(jwtVerifier);
        Mockito.when(client.getClientId()).thenReturn(ISS);
    }

    @Test
    public void testSupport() {
        Assertions.assertThat(provider.supports(JWTAssertionAuthenticationToken.class)).isTrue();
        Assertions.assertThat(provider.supports(IllegalArgumentException.class)).isFalse();
    }

    @Test
    public void testAuthenticateWhenSuccess() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .expirationTime(future)
                        .issuer(ISS)
                        .subject(SUB)
                        .audience(TOKEN_PATH)
                        .jwtID(JTI)
                        .build()
                        .toPayload()
        );

        Mockito.when(jwtVerifier.verify(Mockito.any())).thenReturn(true);

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Authentication ret = provider.authenticate(authenticationToken);
        Assertions.assertThat(ret).isNotNull();
        Assertions.assertThat(ret.isAuthenticated()).isTrue();
        Assertions.assertThat(ret.getPrincipal()).isEqualTo(ISS);
    }

    @Test
    public void testAuthenticateWithPlainAssertionThenException() {
        JWT assertion = new PlainJWT(
                new JWTClaimsSet.Builder().build()
        );
        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);

        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client assertion must be signed.");
    }

    @Test
    public void testAuthenticateWithEncryptedAssertionThenException() {
        JWT assertion = new EncryptedJWT(
                new JWEHeader.Builder(JWEAlgorithm.PBES2_HS256_A128KW, EncryptionMethod.A128GCM).build(),
                new JWTClaimsSet.Builder().build()
        );
        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client assertion must be signed.");
    }

    @Test
    public void testAuthenticateWithInvalidJWTFormatThenException() {
        JWT assertion = getJWS(new Payload("v"));
        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);

        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client assertion payload must be a json.");
    }

    @Test
    public void testAuthenticateWithInvalidNbfThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .notBeforeTime(future)
                        .expirationTime(future)
                        .build()
                        .toPayload()
        );

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client assertion is not valid until : " + future);
    }

    @Test
    public void testAuthenticateWithExpiredAssertionThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .expirationTime(past)
                        .build()
                        .toPayload()
        );

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client assertion already expired.");
    }

    @Test
    public void testAuthenticateWithoutExpirationThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .build()
                        .toPayload()
        );

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client assertion must contain exp.");
    }

    @Test
    public void testAuthenticateWithoutIssuerThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .expirationTime(future)
                        .build()
                        .toPayload()
        );

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client assertion must contain iss.");
    }

    @Test
    public void testAuthenticateWithoutSubjectThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .expirationTime(future)
                        .issuer(ISS)
                        .build()
                        .toPayload()
        );

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client assertion must contain sub.");
    }

    @Test
    public void testAuthenticateMismatchSubAndIssThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .expirationTime(future)
                        .issuer(ISS)
                        .subject("foo")
                        .build()
                        .toPayload()
        );

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Mismatch between sub and aud.");
    }

    @Test
    public void testAuthenticateWithoutAudThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .expirationTime(future)
                        .issuer(ISS)
                        .subject(SUB)
                        .build()
                        .toPayload()
        );

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client assertion must contain aud.");
    }

    @Test
    public void testAuthenticateWithInvalidAudThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .expirationTime(future)
                        .issuer(ISS)
                        .subject(SUB)
                        .audience("foo")
                        .build()
                        .toPayload()
        );

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client assertion must contain issuer or token endpoint path.");
    }

    @Test
    public void testAuthenticateWithoutJTIThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .expirationTime(future)
                        .issuer(ISS)
                        .subject(SUB)
                        .audience(AUD)
                        .build()
                        .toPayload()
        );

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client assertion must contain issuer or token endpoint path.");
    }

    @Test
    public void testAuthenticateUnsupportedClientAuthMethodThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .expirationTime(future)
                        .issuer(ISS)
                        .subject(SUB)
                        .audience(TOKEN_PATH)
                        .jwtID(JTI)
                        .build()
                        .toPayload()
        );
        Mockito.when(client.getTokenEndpointAuthMethod()).thenReturn(ClientAuthMethod.SECRET_POST);

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessage("Client doesnt support client assertion.");
    }

    @Test
    public void testAuthenticateMismatchBetweenJWSAlgAndTokenSigningAlgThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .expirationTime(future)
                        .issuer(ISS)
                        .subject(SUB)
                        .audience(TOKEN_PATH)
                        .jwtID(JTI)
                        .build()
                        .toPayload()
        );

        Mockito.when(client.getTokenEndpointAuthSigningAlg()).thenReturn(JWSAlgorithm.HS256);

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessageStartingWith("Excepted assertion signing alg ");
    }

    @Test
    public void testAuthenticateWithInvalidSignatureThenException() {
        JWT assertion = getJWS(
                new JWTClaimsSet.Builder()
                        .expirationTime(future)
                        .issuer(ISS)
                        .subject(SUB)
                        .audience(TOKEN_PATH)
                        .jwtID(JTI)
                        .build()
                        .toPayload()
        );

        Mockito.when(jwtVerifier.verify(Mockito.any())).thenReturn(false);

        JWTAssertionAuthenticationToken authenticationToken = new JWTAssertionAuthenticationToken(assertion);
        Assertions.assertThatExceptionOfType(BadCredentialsException.class)
                .isThrownBy(() -> provider.authenticate(authenticationToken))
                .withMessageStartingWith("Invalid client assertion signature.");
    }

    private JWT getJWS(Payload payload) {
        try {
            OctetSequenceKey key = new OctetSequenceKeyGenerator(512).generate();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS512).keyID("1").build();
            JWSObject jws = new JWSObject(header, payload);
            JWSSigner signer = new MACSigner(key);
            jws.sign(signer);

            return JWTParser.parse(jws.serialize());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
