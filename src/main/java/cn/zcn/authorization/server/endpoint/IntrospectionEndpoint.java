package cn.zcn.authorization.server.endpoint;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.ExceptionWriter;
import cn.zcn.authorization.server.exception.OAuth2Error;
import com.google.common.base.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;

/**
 * 令牌自省端点
 * 参考规范：https://datatracker.ietf.org/doc/html/rfc7662
 */
public class IntrospectionEndpoint {

    private static final String ACCESS_TOKEN_TYPE_HINT = "access_token";
    private static final String REFRESH_TOKEN_TYPE_HINT = "refresh_token";

    private final static Logger logger = LoggerFactory.getLogger(IntrospectionEndpoint.class);

    private ExceptionWriter exceptionWriter;

    private TokenService tokenService;

    private TokenConverter tokenConverter;

    @RequestMapping(value = ServerConfig.INTROSPECTION_ENDPOINT, method = RequestMethod.POST, consumes = "application/x-www-form-urlencoded", produces = "application/json")
    public ResponseEntity<Map<String, ?>> introspect(@RequestParam(value = "token") String token, @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new InsufficientAuthenticationException("Must be authenticated client before invoke introspection endpoint.");
        }

        if (Strings.isNullOrEmpty(token)) {
            return ResponseEntity.ok(Collections.singletonMap(OAuth2Constants.FIELD.ACTIVE, false));
        }

        String authClientId = null;
        if (authentication instanceof OAuth2Authentication) {
            /*
             * 使用 Access Token 访问该端点，拒绝不是通过客户端模式获得的令牌
             */
            OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) authentication;
            if (!"client_credentials".equals(oAuth2Authentication.getTokenRequest().getGrantType())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value()).build();
            }
        } else {
            // 使用 client credentials 访问该端点
            authClientId = authentication.getName();
        }

        AccessToken accessTokenEntity = null;
        RefreshToken refreshTokenEntity = null;

        if (!Strings.isNullOrEmpty(tokenTypeHint)) {
            if (!tokenTypeHint.equals(ACCESS_TOKEN_TYPE_HINT) && !tokenTypeHint.equals(REFRESH_TOKEN_TYPE_HINT)) {
                throw OAuth2Error.createException(OAuth2Error.INVALID_REQUEST, "Unsupported toke type: " + tokenTypeHint);
            }

            if (ACCESS_TOKEN_TYPE_HINT.equals(tokenTypeHint)) {
                accessTokenEntity = tokenService.getAccessToken(token);
            } else {
                refreshTokenEntity = tokenService.getRefreshToken(token);
            }
        } else {
            //如果请求中没有 tokenTypeHint 字段，依次在访问令牌、刷新令牌中查找
            accessTokenEntity = tokenService.getAccessToken(token);

            if (accessTokenEntity == null) {
                refreshTokenEntity = tokenService.getRefreshToken(token);
            }
        }

        if (accessTokenEntity != null) {
            if (!accessTokenEntity.getClientId().equals(authClientId)) {
                logger.info("Client " + authClientId + " tried to get a token info owned by " + accessTokenEntity.getClientId());

                return ResponseEntity.status(HttpStatus.FORBIDDEN.value()).build();
            }

            return ResponseEntity.ok(tokenConverter.convertAccessToken(accessTokenEntity, authentication));
        } else if (refreshTokenEntity != null) {
            if (!refreshTokenEntity.getClientId().equals(authClientId)) {
                logger.info("Client " + authClientId + " tried to get a  token info owned by " + accessTokenEntity.getClientId());

                return ResponseEntity.status(HttpStatus.FORBIDDEN.value()).build();
            }

            return ResponseEntity.ok(tokenConverter.convertRefreshToken(refreshTokenEntity, authentication));
        } else {
            return ResponseEntity.ok(Collections.singletonMap(OAuth2Constants.FIELD.ACTIVE, false));
        }
    }

    @ExceptionHandler(Exception.class)
    public void handleException(Exception e, HttpServletRequest request, HttpServletResponse response) throws IOException {
        exceptionWriter.write(e, new ServletWebRequest(request, response));
    }

    public void setTokenService(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    public void setTokenConverter(TokenConverter tokenConverter) {
        this.tokenConverter = tokenConverter;
    }

    public void setExceptionWriter(ExceptionWriter exceptionWriter) {
        this.exceptionWriter = exceptionWriter;
    }
}
