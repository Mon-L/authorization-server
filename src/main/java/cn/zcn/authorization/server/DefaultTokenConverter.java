package cn.zcn.authorization.server;

import cn.zcn.authorization.server.utils.OAuth2Utils;
import com.google.common.collect.Maps;
import org.springframework.security.core.Authentication;

import java.util.Map;

public class DefaultTokenConverter implements TokenConverter {

    private final ServerConfig serverConfig;

    public DefaultTokenConverter(ServerConfig serverConfig) {
        this.serverConfig = serverConfig;
    }

    @Override
    public Map<String, ?> convertAccessToken(AccessToken accessToken, Authentication authentication) {
        Map<String, Object> result = Maps.newLinkedHashMap();

        result.put(OAuth2Constants.FIELD.ACTIVE, true);
        result.put(OAuth2Constants.FIELD.SCOPE, OAuth2Utils.joinParameterString(accessToken.getScope()));
        result.put(OAuth2Constants.FIELD.ISS, serverConfig.getIssuer());
        result.put(OAuth2Constants.FIELD.IAT, accessToken.getCreatedAt().getTime() / 1000L);
        result.put(OAuth2Constants.FIELD.CLIENT_ID, accessToken.getClientId());
        result.put(OAuth2Constants.FIELD.TOKEN_TYPE, accessToken.getTokenType());

        if (accessToken.getExpiration() != null) {
            result.put(OAuth2Constants.FIELD.EXP, accessToken.getExpiration().getTime() / 1000L);
        }

        return result;
    }

    @Override
    public Map<String, ?> convertRefreshToken(RefreshToken refreshToken, Authentication authentication) {
        Map<String, Object> result = Maps.newLinkedHashMap();
        result.put(OAuth2Constants.FIELD.ACTIVE, true);
        result.put(OAuth2Constants.FIELD.CLIENT_ID, refreshToken.getClientId());
        result.put(OAuth2Constants.FIELD.SCOPE, OAuth2Utils.joinParameterString(refreshToken.getScope()));

        if (refreshToken.getExpiration() != null) {
            result.put(OAuth2Constants.FIELD.EXP, refreshToken.getExpiration().getTime() / 1000L);
        }

        return result;
    }
}
