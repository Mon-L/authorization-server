package cn.zcn.authorization.server;

import cn.zcn.authorization.server.exception.OAuth2Exception;

public interface AuthorizationCodeService {

    String createAuthorizationCode(OAuth2PreviousAuthentication authentication);

    OAuth2PreviousAuthentication consumeAuthorizationCode(String code) throws OAuth2Exception;
}
