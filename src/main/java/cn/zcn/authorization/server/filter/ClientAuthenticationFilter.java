package cn.zcn.authorization.server.filter;

import cn.zcn.authorization.server.authentication.extractor.AuthenticationExtractor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/**
 * 抽取client credentials，并验证是否有效
 */
public class ClientAuthenticationFilter extends OncePerRequestFilter {

    private RequestMatcher requestMatcher;
    private AuthenticationManager authenticationManager;
    private List<AuthenticationExtractor> authenticationExtractors;
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private AuthenticationFailureHandler authenticationFailureHandler;

    public ClientAuthenticationFilter(RequestMatcher requestMatcher,
                                      List<AuthenticationExtractor> authenticationExtractors,
                                      AuthenticationManager authenticationManager,
                                      AuthenticationSuccessHandler authenticationSuccessHandler,
                                      AuthenticationFailureHandler authenticationFailureHandler) {
        this.requestMatcher = requestMatcher;
        this.authenticationManager = authenticationManager;
        this.authenticationExtractors = authenticationExtractors;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication authentication = null;

            /*
             * 遍历 authenticationExtractors 获取客户端凭证
             */
            for (AuthenticationExtractor extractor : authenticationExtractors) {
                if (extractor.getRequestMatcher().matches(request)) {
                    authentication = extractor.extract(request);
                    if (authentication != null) {
                        break;
                    }
                }
            }

            if (authentication != null) {
                /*
                 * 验证客户端的身份
                 */
                authentication = authenticationManager.authenticate(authentication);
                authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);
            }
            filterChain.doFilter(request, response);
        } catch (AuthenticationException e) {
            authenticationFailureHandler.onAuthenticationFailure(request, response, e);
        }
    }
}
