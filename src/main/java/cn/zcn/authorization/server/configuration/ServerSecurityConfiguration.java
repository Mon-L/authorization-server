package cn.zcn.authorization.server.configuration;

import cn.zcn.authorization.server.configurer.ServerSecurityConfigurer;
import cn.zcn.authorization.server.exception.OAuth2ExceptionWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.List;

@Order(0)
@Configuration
public class ServerSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final ServerSecurityConfigurer serverSecurityConfigurer = new ServerSecurityConfigurer();

    @Autowired
    public void setConfigurers(List<ServerSecurityConfigurationAdapter> configurers) {
        configurers.sort(AnnotationAwareOrderComparator.INSTANCE);

        for (ServerSecurityConfigurationAdapter adapter : configurers) {
            adapter.configure(serverSecurityConfigurer);
        }
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        serverSecurityConfigurer.init(http);
        RequestMatcher requestMatcher = serverSecurityConfigurer.getRequestMatcher();
        OAuth2ExceptionWriter oAuth2ExceptionWriter = http.getSharedObject(OAuth2ExceptionWriter.class);

        http
                .requestMatcher(requestMatcher).authorizeRequests().anyRequest().fullyAuthenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
                .csrf().ignoringRequestMatchers(requestMatcher)
                .and()
                .exceptionHandling()
                .defaultAuthenticationEntryPointFor((request, response, exception) -> {
                    oAuth2ExceptionWriter.write(exception, new ServletWebRequest(request, response));
                    response.flushBuffer();
                }, requestMatcher);

        for (SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> configurer : serverSecurityConfigurer.getConfigurers().values()) {
            http.apply(configurer);
        }
    }
}
