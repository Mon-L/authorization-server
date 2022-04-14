package cn.zcn.authorization.server;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class AuthorizationRequest extends BaseOAuth2Request {

    private final boolean approved;
    private final String redirectUri;
    private final Set<String> responseType;

    public AuthorizationRequest(String clientId, Set<String> scope,
                                Set<String> responseType, String redirectUri,
                                Map<String, String> requestParameters, boolean approved) {
        super(clientId, scope, requestParameters);
        this.approved = approved;
        this.redirectUri = redirectUri;
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
}
