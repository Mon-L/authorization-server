package cn.zcn.authorization.server.authentication;

import com.nimbusds.jwt.JWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.text.ParseException;
import java.util.Collection;

/**
 * 封装Client Assertion
 */
public class JWTAssertionAuthenticationToken extends AbstractAuthenticationToken {

    private final static Logger logger = LoggerFactory.getLogger(JWTAssertionAuthenticationToken.class);

    private JWT jwt;
    private String issuer;

    public JWTAssertionAuthenticationToken(JWT assertion, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        try {
            this.issuer = assertion.getJWTClaimsSet().getIssuer();
        } catch (ParseException e) {
            logger.error("Failed to parse client assertion", e);
        }
        this.jwt = assertion;
        setAuthenticated(true);
    }

    public JWTAssertionAuthenticationToken(JWT assertion) {
        super(null);

        this.jwt = assertion;
        setAuthenticated(false);

        try {
            this.issuer = assertion.getJWTClaimsSet().getIssuer();
        } catch (ParseException e) {
            logger.error("Failed to parse client assertion", e);
        }
    }

    @Override
    public void eraseCredentials() {
        this.jwt = null;
    }

    @Override
    public Object getCredentials() {
        return jwt;
    }

    public JWT getJwt() {
        return jwt;
    }

    @Override
    public Object getPrincipal() {
        return issuer;
    }
}
