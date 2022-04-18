package cn.zcn.authorization.server;

import cn.zcn.authorization.server.exception.OAuth2Error;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import cn.zcn.authorization.server.utils.OAuth2Utils;
import org.springframework.util.StringUtils;

import java.util.Map;

public class DefaultRequestResolver implements RequestResolver {

    @Override
    public AuthorizationRequest resolve2AuthorizationRequest(Map<String, String> parameters) throws OAuth2Exception {
        AuthorizationRequest request = new AuthorizationRequest(
                parameters.get(OAuth2Constants.FIELD.CLIENT_ID),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Constants.FIELD.SCOPE)),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Constants.FIELD.RESPONSE_TYPE)),
                parameters.get(OAuth2Constants.FIELD.REDIRECT_URI),
                parameters,
                false
        );

        if (!StringUtils.hasText(request.getClientId())) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_REQUEST, "Missing client id");
        }

        if (request.getResponseType().isEmpty()) {
            throw OAuth2Error.createException(OAuth2Error.INVALID_REQUEST, "Missing response type");
        }

        return request;
    }

    @Override
    public TokenRequest resolve2TokenRequest(Map<String, String> parameters, Client client) throws OAuth2Exception {
        String clientId = client.getClientId();
        if (parameters.containsKey(OAuth2Constants.FIELD.CLIENT_ID)) {
            parameters.get(OAuth2Constants.FIELD.CLIENT_ID);
        }

        return new TokenRequest(clientId,
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Constants.FIELD.SCOPE)),
                parameters.get(OAuth2Constants.FIELD.GRANT_TYPE),
                parameters
        );
    }
}
