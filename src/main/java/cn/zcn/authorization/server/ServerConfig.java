package cn.zcn.authorization.server;

import java.util.HashMap;
import java.util.Map;

/**
 * 配置认证授权服务的全局配置
 */
public class ServerConfig {
    public final static String AUTHORIZATION_ENDPOINT = "/oauth/authorize";
    public final static String TOKEN_ENDPOINT = "/oauth/token";
    public final static String INTROSPECTION_ENDPOINT = "/oauth/introspect";
    public final static String REVOCATION_ENDPOINT = "/oauth/revoke";

    private final String issuer;
    private final String authorizationEndpoint;
    private final String tokenEndpoint;
    private final String introspectionEndpoint;
    private final String revocationEndpoint;
    private final Map<String, Object> additionalClaims;

    private ServerConfig(String issuer,
                         String authorizationEndpoint,
                         String tokenEndpoint,
                         String introspectionEndpoint,
                         String revocationEndpoint,
                         Map<String, Object> additionalClaims) {
        this.issuer = issuer;
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.introspectionEndpoint = introspectionEndpoint;
        this.revocationEndpoint = revocationEndpoint;
        this.additionalClaims = additionalClaims;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public String getIntrospectionEndpoint() {
        return introspectionEndpoint;
    }

    public String getRevocationEndpoint() {
        return revocationEndpoint;
    }

    public <T> T getClaim(String key) {
        Object v = additionalClaims.get(key);
        return v == null ? null : (T) v;
    }

    public static class Builder {

        private String issuer;
        private String authorizationEndpoint = AUTHORIZATION_ENDPOINT;
        private String tokenEndpoint = TOKEN_ENDPOINT;
        private String introspectionEndpoint = INTROSPECTION_ENDPOINT;
        private String revocationEndpoint = REVOCATION_ENDPOINT;
        private final Map<String, Object> additionalClaims = new HashMap<>();

        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder authorizationEndpoint(String authorizationEndpoint) {
            this.authorizationEndpoint = authorizationEndpoint;
            return this;
        }

        public Builder tokenEndpoint(String tokenEndpoint) {
            this.tokenEndpoint = tokenEndpoint;
            return this;
        }

        public Builder introspectionEndpoint(String introspectionEndpoint) {
            this.introspectionEndpoint = introspectionEndpoint;
            return this;
        }

        public Builder revocationEndpoint(String revocationEndpoint) {
            this.revocationEndpoint = revocationEndpoint;
            return this;
        }

        public Builder additionalClaims(String key, Object val) {
            this.additionalClaims.put(key, val);
            return this;
        }

        public ServerConfig build() {
            return new ServerConfig(issuer,
                    authorizationEndpoint,
                    tokenEndpoint,
                    introspectionEndpoint,
                    revocationEndpoint,
                    additionalClaims
            );
        }
    }
}
