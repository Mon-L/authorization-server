package cn.zcn.authorization.server.authentication.extractor;

import cn.zcn.authorization.server.OAuth2Authentication;
import cn.zcn.authorization.server.TokenService;
import cn.zcn.authorization.server.exception.OAuth2Error;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class OAuth2AuthenticationManager implements AuthenticationManager {

    private TokenService tokenService;

    public OAuth2AuthenticationManager(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication == null) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_TOKEN, "Access token not found.");
        }

        String token = (String) authentication.getPrincipal();
        OAuth2Authentication oauth2Authentication = tokenService.loadAuthenticationWithAccessToken(token);

        if (oauth2Authentication == null) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_TOKEN, "Invalid token :" + token);
        }

        oauth2Authentication.setDetails(authentication.getDetails());
        oauth2Authentication.setAuthenticated(true);
        return oauth2Authentication;
    }
}
