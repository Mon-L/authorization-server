package cn.zcn.authorization.server;

import cn.zcn.authorization.server.exception.OAuth2Exception;

import java.util.Map;

public interface RequestResolver {
    AuthorizationRequest resolve2AuthorizationRequest(Map<String, String> parameters) throws OAuth2Exception;

    TokenRequest resolve2TokenRequest(Map<String, String> parameters, Client client) throws OAuth2Exception;
}
