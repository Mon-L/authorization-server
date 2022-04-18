package cn.zcn.authorization.server;

import java.util.Map;
import java.util.Set;

public class TokenRequest {

    private final String clientId;
    private final String grantType;
    private final Map<String, String> requestParameters;

    private Set<String> scope;

    /**
     * 授权请求，该属性可为空。只有授权码模式、简化模式下才有该属性
     */
    private AuthorizationRequest authorizationRequest;

    /**
     * 令牌请求
     *
     * @param clientId          客户端 ID
     * @param scope             授权范围
     * @param grantType         授权模式
     * @param requestParameters 请求参数
     */
    public TokenRequest(String clientId, Set<String> scope, String grantType, Map<String, String> requestParameters) {
        this.clientId = clientId;
        this.grantType = grantType;
        this.scope = scope;
        this.requestParameters = requestParameters;
    }

    public void setAuthorizationRequest(AuthorizationRequest authorizationRequest) {
        this.authorizationRequest = authorizationRequest;
    }

    /**
     * 授权请求，该属性可为空。只有授权码模式、简化模式下才有该属性
     */
    public AuthorizationRequest getAuthorizationRequest() {
        return authorizationRequest;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getClientId() {
        return clientId;
    }

    public Set<String> getScope() {
        return scope;
    }

    public void setScope(Set<String> scope) {
        this.scope = scope;
    }

    public Map<String, String> getRequestParameters() {
        return requestParameters;
    }
}
