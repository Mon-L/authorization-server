package cn.zcn.authorization.server.grant;

import cn.zcn.authorization.server.AccessToken;
import cn.zcn.authorization.server.Client;
import cn.zcn.authorization.server.TokenRequest;
import cn.zcn.authorization.server.TokenService;
import cn.zcn.authorization.server.exception.OAuth2Error;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import org.springframework.util.Assert;

import java.util.Set;

public abstract class BaseTokenGranter implements TokenGranter {

    private final String supportedGrantType;
    protected TokenService tokenService;

    public BaseTokenGranter(String supportedGrantType, TokenService tokenService) {
        Assert.hasLength(supportedGrantType, "Grant type should not be null.");

        this.supportedGrantType = supportedGrantType;
        this.tokenService = tokenService;
    }

    public AccessToken grant(Client client, TokenRequest tokenRequest) throws OAuth2Exception {
        Set<String> grantTypes = client.getGrantTypes();
        if (grantTypes != null && !grantTypes.contains(supportedGrantType)) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_GRANT, "Client dont support grant type: " + supportedGrantType);
        }

        return doGrant(client, tokenRequest);
    }

    protected abstract AccessToken doGrant(Client client, TokenRequest tokenRequest) throws OAuth2Exception;

    public boolean support(TokenRequest tokenRequest) {
        return supportedGrantType.equals(tokenRequest.getGrantType());
    }
}
