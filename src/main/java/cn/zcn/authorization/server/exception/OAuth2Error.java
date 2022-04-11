package cn.zcn.authorization.server.exception;

import org.springframework.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

public class OAuth2Error {

    public static final OAuth2Error SERVER_ERROR = new OAuth2Error("server_error", HttpStatus.INTERNAL_SERVER_ERROR);
    public static final OAuth2Error UNAUTHORIZED = new OAuth2Error("unauthorized", HttpStatus.UNAUTHORIZED);
    public static final OAuth2Error ACCESS_DENIED = new OAuth2Error("access_denied", HttpStatus.FORBIDDEN);
    public static final OAuth2Error INVALID_CLIENT = new OAuth2Error("invalid_client", HttpStatus.UNAUTHORIZED);
    public static final OAuth2Error INVALID_GRANT = new OAuth2Error("invalid_grant", HttpStatus.UNAUTHORIZED);
    public static final OAuth2Error INVALID_REQUEST = new OAuth2Error("invalid_request", HttpStatus.BAD_REQUEST);
    public static final OAuth2Error INVALID_SCOPE = new OAuth2Error("invalid_scope", HttpStatus.BAD_REQUEST);
    public static final OAuth2Error UNSUPPORTED_RESPONSE_TYPE = new OAuth2Error("unsupported_response_type", HttpStatus.BAD_REQUEST);

    private static final Map<String, OAuth2Error> lookup = new HashMap<>();

    static {
        lookup.put(SERVER_ERROR.errorCode, SERVER_ERROR);
        lookup.put(UNAUTHORIZED.errorCode, UNAUTHORIZED);
        lookup.put(ACCESS_DENIED.errorCode, ACCESS_DENIED);
        lookup.put(INVALID_CLIENT.errorCode, INVALID_CLIENT);
        lookup.put(INVALID_GRANT.errorCode, INVALID_GRANT);
        lookup.put(INVALID_REQUEST.errorCode, INVALID_REQUEST);
        lookup.put(INVALID_SCOPE.errorCode, INVALID_SCOPE);
        lookup.put(UNSUPPORTED_RESPONSE_TYPE.errorCode, UNSUPPORTED_RESPONSE_TYPE);
    }

    private final String errorCode;
    private final HttpStatus httpStatus;

    public OAuth2Error(String errorCode, HttpStatus httpStatus) {
        this.errorCode = errorCode;
        this.httpStatus = httpStatus;
    }


    public String getErrorCode() {
        return errorCode;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public static OAuth2Error valueOf(String errorCode) {
        OAuth2Error oAuth2Error = lookup.get(errorCode);
        if (oAuth2Error == null) {
            return new OAuth2Error(errorCode, HttpStatus.BAD_REQUEST);
        }

        return oAuth2Error;
    }

    public static OAuth2Exception create(OAuth2Error oAuth2Error) {
        OAuth2Exception exception = new OAuth2Exception(oAuth2Error.getErrorCode());
        exception.httpStatus(oAuth2Error.httpStatus);
        return exception;
    }

    public static OAuth2Exception create(OAuth2Error oAuth2Error, String message) {
        OAuth2Exception exception = new OAuth2Exception(oAuth2Error.getErrorCode(), message);
        exception.httpStatus(oAuth2Error.httpStatus);
        return exception;
    }

    public static OAuth2Exception create(OAuth2Error oAuth2Error, String message, Exception source) {
        OAuth2Exception exception = new OAuth2Exception(oAuth2Error.getErrorCode(), message, source);
        exception.httpStatus(oAuth2Error.httpStatus);
        return exception;
    }
}
