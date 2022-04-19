package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.OAuth2AuthenticationEntryPoint;
import cn.zcn.authorization.server.ServerConfig;
import cn.zcn.authorization.server.TokenService;
import cn.zcn.authorization.server.authentication.extractor.OAuth2AuthenticationManager;
import cn.zcn.authorization.server.filter.TokenAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * 配置使用 access token 访问受保护资源的功能。该类会在{@code HttpSecurity}中添加一个过滤器，用于验证 access token 是否有效
 */
public class TokenAuthenticationConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    /**
     * 用于匹配需要使用 access token 访问受保护资源的请求
     */
    private RequestMatcher requestMatcher;

    /**
     * 用于认证 access token 是否有效
     */
    private AuthenticationManager authenticationManager;

    /**
     * 当 access token 无效时的后置处理器
     */
    private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

    @Override
    public void init(HttpSecurity builder) throws Exception {
        if (authenticationManager == null) {
            authenticationManager = new OAuth2AuthenticationManager(builder.getSharedObject(TokenService.class));
        }

        if (requestMatcher == null) {
            ServerConfig serverConfig = builder.getSharedObject(ServerConfig.class);

            //默认只拦截 OAuth2 的端点
            requestMatcher = new OrRequestMatcher(
                    new AntPathRequestMatcher(serverConfig.getIntrospectionEndpoint()),
                    new AntPathRequestMatcher(serverConfig.getRevocationEndpoint())
            );
        }
    }

    @Override
    public void configure(HttpSecurity builder) {
        TokenAuthenticationFilter filter = new TokenAuthenticationFilter();
        filter.setRequestMatcher(requestMatcher);
        filter.setAuthenticationEntryPoint(authenticationEntryPoint);
        filter.setAuthenticationManager(authenticationManager);
        filter.setStateless(true);

        builder.addFilterAfter(postProcess(filter), AbstractPreAuthenticatedProcessingFilter.class);
    }

    public TokenAuthenticationConfigurer authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }

    public TokenAuthenticationConfigurer authenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        return this;
    }

    public TokenAuthenticationConfigurer requestMatcher(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
        return this;
    }
}
