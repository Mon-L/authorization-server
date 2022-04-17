package cn.zcn.authorization.server;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class AuthorizationRequest {

    private final String clientId;
    private final String redirectUri;
    private final Set<String> responseType;
    private final Map<String, String> requestParameters;

    private Set<String> scope;
    private boolean approved;

    public AuthorizationRequest(String clientId, Set<String> scope,
                                Set<String> responseType, String redirectUri,
                                Map<String, String> requestParameters, boolean approved) {
        this.clientId = clientId;
        this.scope = scope;
        this.approved = approved;
        this.redirectUri = redirectUri;
        this.requestParameters = requestParameters;
        this.responseType = Collections.unmodifiableSet(responseType);
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public Set<String> getResponseType() {
        return responseType;
    }

    public boolean isApproved() {
        return approved;
    }

    public String getClientId() {
        return clientId;
    }

    public Set<String> getScope() {
        return scope;
    }

    public Map<String, String> getRequestParameters() {
        return Collections.unmodifiableMap(requestParameters);
    }

    public void setScope(Set<String> scope) {
        this.scope = scope;
    }

    public void setApproved(boolean approved) {
        this.approved = approved;
    }
}
