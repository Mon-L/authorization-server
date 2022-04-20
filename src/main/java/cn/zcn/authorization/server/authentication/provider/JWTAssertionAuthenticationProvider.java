package cn.zcn.authorization.server.authentication.provider;


import cn.zcn.authorization.server.Client;
import cn.zcn.authorization.server.ClientAuthMethod;
import cn.zcn.authorization.server.ClientService;
import cn.zcn.authorization.server.ServerConfig;
import cn.zcn.authorization.server.authentication.JWTAssertionAuthenticationToken;
import cn.zcn.authorization.server.exception.JOSERuntimeException;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import cn.zcn.authorization.server.jose.ClientJOSEService;
import cn.zcn.authorization.server.jose.JWTVerifier;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.text.ParseException;
import java.util.Date;

/**
 * 验证 Client Assertion 是否有效
 * 参考规范: https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
 */
public class JWTAssertionAuthenticationProvider implements AuthenticationProvider {

    private final ServerConfig serverConfig;
    private final ClientService clientService;
    private final ClientJOSEService clientJOSEService;

    public JWTAssertionAuthenticationProvider(ServerConfig serverConfig, ClientService clientService, ClientJOSEService clientJOSEService) {
        this.serverConfig = serverConfig;
        this.clientService = clientService;
        this.clientJOSEService = clientJOSEService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JWTAssertionAuthenticationToken jwtToken = (JWTAssertionAuthenticationToken) authentication;
        JWT assertion = jwtToken.getAssertion();

        if (!(assertion instanceof SignedJWT)) {
            throw new BadCredentialsException("Client assertion must be signed.");
        }

        JWTClaimsSet claims;
        try {
            claims = assertion.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new BadCredentialsException("Client assertion payload must be a json.");
        }

        Date now = new Date();
        if (claims.getNotBeforeTime() != null) {
            if (now.before(claims.getNotBeforeTime())) {
                throw new BadCredentialsException("Client assertion is not valid until : " + claims.getNotBeforeTime());
            }
        }

        if (claims.getExpirationTime() == null) {
            throw new BadCredentialsException("Client assertion must contain exp.");
        } else if (claims.getExpirationTime().before(now)) {
            throw new BadCredentialsException("Client assertion already expired.");
        }

        if (claims.getIssuer() == null) {
            throw new BadCredentialsException("Client assertion must contain iss.");
        }

        if (claims.getSubject() == null) {
            throw new BadCredentialsException("Client assertion must contain sub.");
        }

        if (!claims.getIssuer().equals(claims.getSubject())) {
            throw new BadCredentialsException("Mismatch between sub and aud.");
        }

        if (claims.getAudience().isEmpty()) {
            throw new BadCredentialsException("Client assertion must contain aud.");
        } else if (!claims.getAudience().contains(serverConfig.getIssuer()) && !claims.getAudience().contains(serverConfig.getTokenEndpoint())) {
            throw new BadCredentialsException("Client assertion must contain issuer or token endpoint path.");
        }

        if (claims.getJWTID() == null) {
            throw new BadCredentialsException("Client assertion must contain jti.");
        }

        try {
            SignedJWT signedJWT = (SignedJWT) assertion;
            Client client = clientService.loadClientByClientId(claims.getIssuer());

            if (client.getTokenEndpointAuthMethod() == null ||
                    client.getTokenEndpointAuthMethod().equals(ClientAuthMethod.NONE) ||
                    client.getTokenEndpointAuthMethod().equals(ClientAuthMethod.SECRET_BASIC) ||
                    client.getTokenEndpointAuthMethod().equals(ClientAuthMethod.SECRET_POST)) {

                throw new BadCredentialsException("Client doesnt support client assertion.");
            }

            JWSAlgorithm alg = signedJWT.getHeader().getAlgorithm();
            if (client.getTokenEndpointAuthSigningAlg() != signedJWT.getHeader().getAlgorithm()) {
                throw new BadCredentialsException("Excepted assertion signing alg " + client.getTokenEndpointAuthSigningAlg().getName() + ", but got" + alg.getName());
            }

            JWTVerifier jwtVerifier = clientJOSEService.getVerifier(client, alg);
            if (!jwtVerifier.verify(signedJWT)) {
                throw new BadCredentialsException("Invalid client assertion signature.");
            }

            return new JWTAssertionAuthenticationToken(assertion, client.getAuthorities());
        } catch (JOSERuntimeException e) {
            throw new BadCredentialsException("Failed to load client signature verifier.");
        } catch (OAuth2Exception e) {
            throw new BadCredentialsException("Failed to authenticate client.", e);
        }
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(JWTAssertionAuthenticationToken.class);
    }
}
