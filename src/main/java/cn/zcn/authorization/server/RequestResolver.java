package cn.zcn.authorization.server;

import cn.zcn.authorization.server.exception.OAuth2Exception;

import java.util.Map;

public interface RequestResolver {
    AuthorizationRequest resolve2AuthorizationRequest(Map<String, String> parameters) throws OAuth2Exception;
}
