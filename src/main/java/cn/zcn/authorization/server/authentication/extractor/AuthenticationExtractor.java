package cn.zcn.authorization.server.authentication.extractor;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;

/**
 * 用于抽取客户端凭证
 */
public interface AuthenticationExtractor {

    /**
     * 获取客户端凭证
     */
    Authentication extract(HttpServletRequest request) throws AuthenticationException;

    /**
     * 获取请求匹配器。用于验证 {@link AuthenticationExtractor} 是否支持该请求
     */
    RequestMatcher getRequestMatcher();
}
