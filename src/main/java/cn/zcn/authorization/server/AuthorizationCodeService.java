package cn.zcn.authorization.server;

import cn.zcn.authorization.server.exception.OAuth2Exception;

public interface AuthorizationCodeService {

    String createAuthorizationCode(UserApprovalAuthentication authentication) throws OAuth2Exception;

    UserApprovalAuthentication consumeAuthorizationCode(String code) throws OAuth2Exception;
}
