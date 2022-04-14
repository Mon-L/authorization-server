package cn.zcn.authorization.server;


import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class BaseOAuth2Request {

    private final String clientId;
    private final Set<String> scope;
    private final Map<String, String> requestParameters;

    public BaseOAuth2Request(String clientId, Set<String> scope, Map<String, String> requestParameters) {
        this.clientId = clientId;
        this.scope = scope;
        this.requestParameters = requestParameters;
    }

    public String getClientId() {
        return clientId;
    }

    public Set<String> getScope() {
        return scope;
    }

    public void removeRequestParameter(String key) {
        requestParameters.remove(key);
    }

    public Map<String, String> getRequestParameters() {
        return Collections.unmodifiableMap(requestParameters);
    }
}
