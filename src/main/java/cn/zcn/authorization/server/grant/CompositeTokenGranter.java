package cn.zcn.authorization.server.grant;

import cn.zcn.authorization.server.AccessToken;
import cn.zcn.authorization.server.Client;
import cn.zcn.authorization.server.TokenRequest;
import cn.zcn.authorization.server.exception.OAuth2Exception;

import java.util.ArrayList;
import java.util.List;

public class CompositeTokenGranter implements TokenGranter {

    private final List<TokenGranter> tokenGranters;

    public CompositeTokenGranter() {
        this.tokenGranters = new ArrayList<>();
    }

    @Override
    public AccessToken grant(Client client, TokenRequest tokenRequest) throws OAuth2Exception {
        for (TokenGranter granter : tokenGranters) {
            AccessToken accessToken = granter.grant(client, tokenRequest);
            if (accessToken != null) {
                return accessToken;
            }
        }
        return null;
    }

    public void addTokenGranter(TokenGranter tokenGranter) {
        tokenGranters.add(tokenGranter);
    }
}
