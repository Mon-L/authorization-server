package cn.zcn.authorization.server;

import java.util.Date;
import java.util.Map;
import java.util.Set;

public class TestingAccessToken implements AccessToken {

    private String clientId;
    private TokenType tokenType;
    private String value;
    private Set<String> scope;
    private RefreshToken refreshToken;
    private Date createdAt;
    private Date expiration;

    private Map<String, Object> additionalInformation;

    @Override
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @Override
    public TokenType getTokenType() {
        return tokenType;
    }

    public void setTokenType(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    @Override
    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public Set<String> getScope() {
        return scope;
    }

    public void setScope(Set<String> scope) {
        this.scope = scope;
    }

    @Override
    public RefreshToken getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }

    @Override
    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public boolean isExpired() {
        return getExpiration() != null && System.currentTimeMillis() > getExpiration().getTime();
    }

    @Override
    public int getExpiresIn() {
        if (getExpiration() == null) {
            return -1;
        } else {
            int secondsRemaining = (int) ((getExpiration().getTime() - System.currentTimeMillis()) / 1000);
            if (isExpired()) {
                return 0;
            } else {
                return secondsRemaining;
            }
        }
    }

    @Override
    public Date getExpiration() {
        return expiration;
    }

    public void setExpiration(Date expiration) {
        this.expiration = expiration;
    }

    @Override
    public Map<String, Object> getAdditionalInformation() {
        return additionalInformation;
    }

    public void setAdditionalInformation(Map<String, Object> additionalInformation) {
        this.additionalInformation = additionalInformation;
    }
}
