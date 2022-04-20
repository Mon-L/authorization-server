package cn.zcn.authorization.server.filter;

import cn.zcn.authorization.server.OAuth2AuthenticationEntryPoint;
import cn.zcn.authorization.server.authentication.extractor.AuthenticationExtractor;
import cn.zcn.authorization.server.authentication.extractor.BearerTokenExtractor;
import cn.zcn.authorization.server.exception.OAuth2Exception;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 拦截指定请求并校验请求头中携带的 Bearer Access Token 是否有效
 */
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationExtractor tokenExtractor = new BearerTokenExtractor();

    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    /**
     * 请求匹配器，匹配需要拦截的请求
     */
    private RequestMatcher requestMatcher;

    /**
     * 访问令牌验证器
     */
    private AuthenticationManager authenticationManager;

    private boolean stateless = true;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication authentication = tokenExtractor.extract(request);
            if (authentication == null) {
                if (stateless && isAuthenticated()) {
                    SecurityContextHolder.clearContext();
                }
            } else {
                if (authentication instanceof AbstractAuthenticationToken) {
                    ((AbstractAuthenticationToken) authentication).setDetails(authentication.getPrincipal());
                }

                Authentication authResult = authenticationManager.authenticate(authentication);

                SecurityContextHolder.getContext().setAuthentication(authResult);
            }
        } catch (OAuth2Exception e) {
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(request, response, new InsufficientAuthenticationException(e.getMessage(), e));
            return;
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected void initFilterBean() {
        Assert.state(authenticationManager != null, "AuthenticationManager is required");
        Assert.state(requestMatcher != null, "RequestMatcher is required");
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null && !(authentication instanceof AnonymousAuthenticationToken);
    }

    public void setStateless(boolean stateless) {
        this.stateless = stateless;
    }

    public void setRequestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }
}
