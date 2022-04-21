package cn.zcn.authorization.server;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class AuthorizationRequest implements Serializable {

    private final String clientId;
    private final Set<String> responseType;

    /**
     * 包含原始授权请求的参数并且可以修改
     */
    private final Map<String, String> parameters;

    /**
     * 保存原始授权请求参数，不可修改
     */
    private final Map<String, String> originalParameters;

    private String state;
    private String redirectUri;
    private Set<String> scope;
    private boolean approved;

    public AuthorizationRequest(String clientId, Set<String> scope,
                                Set<String> responseType, String redirectUri,
                                Map<String, String> requestParameters, boolean approved) {
        this.clientId = clientId;
        this.scope = Collections.unmodifiableSet(scope);
        this.approved = approved;
        this.redirectUri = redirectUri;
        this.responseType = Collections.unmodifiableSet(responseType);
        this.parameters = new HashMap<>(requestParameters);
        this.originalParameters = Collections.unmodifiableMap(new HashMap<>(requestParameters));

        if (requestParameters.containsKey(OAuth2Constants.FIELD.STATE)) {
            this.state = requestParameters.get(OAuth2Constants.FIELD.STATE);
        }
    }

    public String getClientId() {
        return clientId;
    }

    public Set<String> getResponseType() {
        return responseType;
    }

    public boolean isApproved() {
        return approved;
    }

    public void setApproved(boolean approved) {
        this.approved = approved;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public Set<String> getScope() {
        return scope;
    }

    public void setScope(Set<String> scope) {
        this.scope = scope;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public Map<String, String> getOriginalParameters() {
        return originalParameters;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public String getStringParameter(String key) {
        return parameters.get(key);
    }

    public Integer getIntegerParameter(String key) {
        if (parameters.containsKey(key)) {
            return Integer.valueOf(parameters.get(key));
        }

        return null;
    }
}
