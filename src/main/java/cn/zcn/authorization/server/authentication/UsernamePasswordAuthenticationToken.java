package cn.zcn.authorization.server.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class UsernamePasswordAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credential;

    public UsernamePasswordAuthenticationToken(Object principal, Object credential, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credential = credential;
        setAuthenticated(true);
    }

    public UsernamePasswordAuthenticationToken(Object principal, Object credential) {
        super(null);
        this.principal = principal;
        this.credential = credential;
        setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        this.credential = null;
    }

    @Override
    public Object getCredentials() {
        return credential;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}