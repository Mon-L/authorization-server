package cn.zcn.authorization.server;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;

public class OAuth2Authentication extends AbstractAuthenticationToken {

    private final TokenRequest tokenRequest;
    private final Authentication authentication;

    /**
     * OAuth2 授权凭证.
     *
     * @param tokenRequest   令牌请求，包含令牌请求的所有参数
     * @param authentication
     */
    public OAuth2Authentication(@NonNull TokenRequest tokenRequest, @NonNull Authentication authentication) {
        super(authentication.getAuthorities());
        this.tokenRequest = tokenRequest;
        this.authentication = authentication;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return authentication == null ? tokenRequest.getClientId() : authentication.getPrincipal();
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        if (CredentialsContainer.class.isAssignableFrom(authentication.getClass())) {
            ((CredentialsContainer) authentication).eraseCredentials();
        }
    }

    public TokenRequest getTokenRequest() {
        return tokenRequest;
    }

    public Authentication getAuthentication() {
        return authentication;
    }
}
