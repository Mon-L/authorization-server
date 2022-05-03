package cn.zcn.authorization.server;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import cn.zcn.authorization.server.exception.OAuth2Error;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import cn.zcn.authorization.server.jose.ClientJOSEService;
import cn.zcn.authorization.server.jose.JWTDecrypter;
import cn.zcn.authorization.server.jose.JWTVerifier;
import cn.zcn.authorization.server.utils.OAuth2Utils;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.*;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.util.Map;
import java.util.Set;

public class DefaultRequestResolver implements RequestResolver {

    private final ServerConfig serverConfig;
    private final ClientService clientService;
    private final JWTDecrypter jwtDecrypter;
    private final ClientJOSEService clientJOSEService;

    public DefaultRequestResolver(ServerConfig serverConfig, ClientService clientService, JWTDecrypter jwtDecrypter, ClientJOSEService clientJOSEService) {
        this.serverConfig = serverConfig;
        this.clientService = clientService;
        this.jwtDecrypter = jwtDecrypter;
        this.clientJOSEService = clientJOSEService;
    }

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
            throw OAuth2Exception.make(OAuth2Error.INVALID_REQUEST, "Missing client id");
        }

        if (request.getResponseType().isEmpty()) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_REQUEST, "Missing response type");
        }

        if (parameters.containsKey(OAuth2Constants.FIELD.REQUEST)) {
            parseRequestObject(request);
        }

        return request;
    }

    /**
     * 解析授权请求中的 request object
     * 参考规范：https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
     *
     * @param authorizationRequest 授权请求
     */
    private void parseRequestObject(AuthorizationRequest authorizationRequest) throws OAuth2Exception {
        Client client = clientService.loadClientByClientId(authorizationRequest.getClientId());

        JWT jwt;
        try {
            jwt = JWTParser.parse(authorizationRequest.getOriginalParameters().get(OAuth2Constants.FIELD.REQUEST));
        } catch (ParseException e) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_REQUEST, "Failed to parse request parameters.");
        }

        try {
            if (jwt instanceof PlainJWT) {

                JWSAlgorithm requestObjectSigningAlg = client.getRequestObjectSigningAlg();
                if (requestObjectSigningAlg != null && !JWSAlgorithm.NONE.equals(requestObjectSigningAlg)) {
                    throw OAuth2Exception.make(OAuth2Error.INVALID_REQUEST, "Excepted signed request object, but got plain jwt.");
                }

            } else if (jwt instanceof SignedJWT) {

                verifySignature(client, (SignedJWT) jwt);

            } else if (jwt instanceof EncryptedJWT) {

                EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;
                jwtDecrypter.decrypt(encryptedJWT);

                SignedJWT signedJWT = encryptedJWT.getPayload().toSignedJWT();
                if (signedJWT != null) {
                    verifySignature(client, signedJWT);
                }

            }
        } catch (JOSERuntimeException e) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_REQUEST, e.getMessage(), e);
        }

        try {
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            if (!client.getClientId().equals(claims.getIssuer())) {
                throw OAuth2Exception.make(OAuth2Error.INVALID_REQUEST, "Mismatch between request object iss and client id");
            }

            if (claims.getAudience() == null || !claims.getAudience().contains(serverConfig.getIssuer())) {
                throw OAuth2Exception.make(OAuth2Error.INVALID_REQUEST, "Request object aud must contain issuer.");
            }

            String clientId = claims.getStringClaim(OAuth2Constants.FIELD.CLIENT_ID);
            if (StringUtils.hasText(clientId) && clientId.equals(client.getClientId())) {
                throw OAuth2Exception.make(OAuth2Error.INVALID_REQUEST, "Mismatch between request object and authorization parameter for client_id.");
            }

            Set<String> responseTypes = OAuth2Utils.parseParameterList(claims.getStringClaim(OAuth2Constants.FIELD.RESPONSE_TYPE));
            if (!responseTypes.isEmpty()) {
                if (!responseTypes.equals(authorizationRequest.getResponseType())) {
                    throw OAuth2Exception.make(OAuth2Error.INVALID_REQUEST, "Mismatch between request object and authorization parameter for response_type");
                }
            }

            /*
             * request object 中含有和授权请求中一样的参数，以 request object 中的为准。
             */
            String redirectUri = claims.getStringClaim(OAuth2Constants.FIELD.REDIRECT_URI);
            if (redirectUri != null) {
                authorizationRequest.setRedirectUri(redirectUri);
            }

            String state = claims.getStringClaim(OAuth2Constants.FIELD.STATE);
            if (state != null) {
                authorizationRequest.setState(state);
            }

            String nonce = claims.getStringClaim(OAuth2Constants.FIELD.NONCE);
            if (nonce != null) {
                authorizationRequest.getParameters().put(OAuth2Constants.FIELD.NONCE, nonce);
            }

            Set<String> scope = OAuth2Utils.parseParameterList(claims.getStringClaim(OAuth2Constants.FIELD.SCOPE));
            if (!scope.isEmpty()) {
                authorizationRequest.setScope(scope);
            }

            String display = claims.getStringClaim(OAuth2Constants.FIELD.DISPLAY);
            if (display != null) {
                authorizationRequest.getParameters().put(OAuth2Constants.FIELD.DISPLAY, display);
            }

            String prompt = claims.getStringClaim(OAuth2Constants.FIELD.PROMPT);
            if (prompt != null) {
                authorizationRequest.getParameters().put(OAuth2Constants.FIELD.PROMPT, prompt);
            }

            Integer maxAge = claims.getIntegerClaim(OAuth2Constants.FIELD.MAX_AGE);
            if (maxAge != null) {
                authorizationRequest.getParameters().put(OAuth2Constants.FIELD.MAX_AGE, maxAge.toString());
            }
        } catch (ParseException e) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_REQUEST, "Failed to parse request object payload.");
        }
    }

    private void verifySignature(Client client, SignedJWT signedJWT) throws OAuth2Exception {
        JWTVerifier jwtVerifier = clientJOSEService.getVerifier(client, signedJWT.getHeader().getAlgorithm());

        if (jwtVerifier.verify(signedJWT)) {
            throw OAuth2Exception.make(OAuth2Error.INVALID_REQUEST, "Invalid request object signature.");
        }
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
