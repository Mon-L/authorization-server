package cn.zcn.authorization.server.configuration;

import cn.zcn.authorization.server.RequestMappingDetector;
import cn.zcn.authorization.server.configurer.AuthorizationServerConfigurer;
import cn.zcn.authorization.server.endpoint.AuthorizationEndpoint;
import cn.zcn.authorization.server.endpoint.IntrospectionEndpoint;
import cn.zcn.authorization.server.endpoint.RevocationEndpoint;
import cn.zcn.authorization.server.endpoint.TokenEndpoint;
import cn.zcn.authorization.server.exception.ExceptionWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.List;

@Configuration
public class AuthorizationServerConfiguration extends WebSecurityConfigurerAdapter {

    private final AuthorizationServerConfigurer serverConfigurer = new AuthorizationServerConfigurer();

    @Autowired
    public void setConfigurers(List<AuthorizationServerConfigurationAdapter> configurers) {
        configurers.sort(AnnotationAwareOrderComparator.INSTANCE);

        for (AuthorizationServerConfigurationAdapter adapter : configurers) {
            adapter.configure(serverConfigurer);
        }
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.setSharedObject(RequestMappingDetector.class, requestMappingDetector());
        http.setSharedObject(AuthorizationEndpoint.class, authorizationEndpoint());
        http.setSharedObject(TokenEndpoint.class, tokenEndpoint());
        http.setSharedObject(IntrospectionEndpoint.class, introspectionEndpoint());
        http.setSharedObject(RevocationEndpoint.class, revocationEndpoint());

        serverConfigurer.init(http);

        RequestMatcher requestMatcher = serverConfigurer.getRequestMatcher();
        ExceptionWriter exceptionWriter = http.getSharedObject(ExceptionWriter.class);

        http
                .requestMatcher(requestMatcher).authorizeRequests().anyRequest().fullyAuthenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
                .csrf().ignoringRequestMatchers(requestMatcher)
                .and()
                .exceptionHandling()
                .defaultAuthenticationEntryPointFor((request, response, exception) -> {
                    exceptionWriter.write(exception, new ServletWebRequest(request, response));
                    response.flushBuffer();
                }, requestMatcher);

        for (SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> configurer : serverConfigurer.getConfigurers().values()) {
            http.apply(configurer);
        }
    }

    @Bean
    public RequestMappingDetector requestMappingDetector() {
        return new RequestMappingDetector();
    }

    /**
     * 授权端点实例。该类不含{@link org.springframework.stereotype.Controller}，Spring不会解析它方法上的{@link RequestMapping}注解
     *
     * @return AuthorizationEndpoint
     */
    @Bean
    public AuthorizationEndpoint authorizationEndpoint() {
        return new AuthorizationEndpoint();
    }

    /**
     * 令牌端点实例。该类不含 {@link org.springframework.stereotype.Controller}，Spring不会解析它方法上的 {@link RequestMapping} 注解
     *
     * @return TokenEndpoint
     */
    @Bean
    public TokenEndpoint tokenEndpoint() {
        return new TokenEndpoint();
    }

    /**
     * 令牌自省端点实例。该类不含 {@link org.springframework.stereotype.Controller}，Spring不会解析它方法上的 {@link RequestMapping} 注解
     *
     * @return IntrospectionEndpoint
     */
    @Bean
    public IntrospectionEndpoint introspectionEndpoint() {
        return new IntrospectionEndpoint();
    }

    /**
     * 令牌吊销端点实例。该类不含 {@link org.springframework.stereotype.Controller}，Spring不会解析它方法上的 {@link RequestMapping} 注解
     *
     * @return RevocationEndpoint
     */
    @Bean
    public RevocationEndpoint revocationEndpoint() {
        return new RevocationEndpoint();
    }
}
