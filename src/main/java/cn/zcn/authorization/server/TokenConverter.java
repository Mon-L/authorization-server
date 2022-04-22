package cn.zcn.authorization.server;

import org.springframework.security.core.Authentication;

import java.util.Map;

public interface TokenConverter {

    Map<String, ?> convertAccessToken(AccessToken token, Authentication authentication);

    Map<String, ?> convertRefreshToken(RefreshToken token, Authentication authentication);
}
