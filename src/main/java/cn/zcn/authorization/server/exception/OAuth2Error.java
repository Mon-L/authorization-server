package cn.zcn.authorization.server.exception;

import org.springframework.http.HttpStatus;

public class OAuth2Error {

    public static final OAuth2Error SERVER_ERROR = new OAuth2Error("server_error", HttpStatus.INTERNAL_SERVER_ERROR);
    public static final OAuth2Error UNAUTHORIZED = new OAuth2Error("unauthorized", HttpStatus.UNAUTHORIZED);
    public static final OAuth2Error ACCESS_DENIED = new OAuth2Error("access_denied", HttpStatus.FORBIDDEN);
    public static final OAuth2Error INVALID_CLIENT = new OAuth2Error("invalid_client", HttpStatus.UNAUTHORIZED);
    public static final OAuth2Error INVALID_GRANT = new OAuth2Error("invalid_grant", HttpStatus.UNAUTHORIZED);
    public static final OAuth2Error INVALID_REQUEST = new OAuth2Error("invalid_request", HttpStatus.BAD_REQUEST);
    public static final OAuth2Error INVALID_SCOPE = new OAuth2Error("invalid_scope", HttpStatus.BAD_REQUEST);
    public static final OAuth2Error INVALID_TOKEN = new OAuth2Error("invalid_token", HttpStatus.UNAUTHORIZED);
    public static final OAuth2Error UNSUPPORTED_RESPONSE_TYPE = new OAuth2Error("unsupported_response_type", HttpStatus.BAD_REQUEST);

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
}
