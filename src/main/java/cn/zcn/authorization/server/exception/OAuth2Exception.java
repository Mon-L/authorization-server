package cn.zcn.authorization.server.exception;

import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class OAuth2Exception extends RuntimeException {

    private final String errorCode;

    private String errorDescription;

    private String errorUri;

    private Map<String, Object> additionParameters;

    private HttpStatus httpStatus = HttpStatus.BAD_REQUEST;

    public OAuth2Exception(String errorCode) {
        super();
        this.errorCode = errorCode;
    }

    public OAuth2Exception(String errorCode, String errorDescription) {
        super(errorDescription);
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }

    public OAuth2Exception(String errorCode, String errorDescription, Throwable throwable) {
        super(errorDescription, throwable);
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }

    public OAuth2Exception errorUri(String errorUri) {
        this.errorUri = errorUri;
        return this;
    }

    public OAuth2Exception httpStatus(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
        return this;
    }

    public OAuth2Exception additionParameter(String key, Object val) {
        if (!StringUtils.hasText(key)) {
            return this;
        }

        if (additionParameters == null) {
            additionParameters = new HashMap<>();
        }
        additionParameters.put(key, val);

        return this;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public String getErrorUri() {
        return errorUri;
    }

    public Map<String, Object> getAdditionParameters() {
        return Collections.unmodifiableMap(additionParameters);
    }

    @Override
    public String toString() {
        return "OAuth2Exception{" +
                "errorCode='" + errorCode + '\'' +
                ", errorDescription='" + errorDescription +
                '}';
    }

}
