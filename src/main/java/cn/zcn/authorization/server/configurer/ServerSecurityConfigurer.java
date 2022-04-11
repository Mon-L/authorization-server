package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.ClientService;
import cn.zcn.authorization.server.ServerConfig;
import cn.zcn.authorization.server.exception.DefaultOAuth2ExceptionWriter;
import cn.zcn.authorization.server.exception.OAuth2ExceptionWriter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 服务配置类，包含服务所有可配置的 {@link SecurityConfigurerAdapter}
 */
public class ServerSecurityConfigurer {

    private final Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>,
            SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> configurers = createConfigurers();

    private RequestMatcher requestMatcher;
    private ClientService clientService;

    private ServerConfig serverConfig = new ServerConfig.Builder().build();
    private OAuth2ExceptionWriter exceptionWriter = new DefaultOAuth2ExceptionWriter();

    public final void init(HttpSecurity builder) {
        Assert.notNull(clientService, "ClientService must not be null.");

        builder.getSharedObjects().put(ServerConfig.class, serverConfig);
        builder.getSharedObjects().put(ClientService.class, clientService);
        builder.getSharedObjects().put(OAuth2ExceptionWriter.class, exceptionWriter);
    }

    public ServerSecurityConfigurer clientService(ClientService clientService) {
        this.clientService = clientService;
        return this;
    }

    public ServerSecurityConfigurer providerConfig(ServerConfig serverConfig) {
        this.serverConfig = serverConfig;
        return this;
    }

    public ServerSecurityConfigurer exceptionWriter(OAuth2ExceptionWriter exceptionWriter) {
        this.exceptionWriter = exceptionWriter;
        return this;
    }

    public ServerSecurityConfigurer authorizationEndpoint(Customizer<AuthorizationEndpointConfigurer> configurer) {
        configurer.customize(getConfigurer(AuthorizationEndpointConfigurer.class));
        return this;
    }

    public ServerSecurityConfigurer tokenEndpoint(Customizer<TokenEndpointConfigurer> configurer) {
        configurer.customize(getConfigurer(TokenEndpointConfigurer.class));
        return this;
    }

    public ServerSecurityConfigurer clientAuthentication(Customizer<ClientAuthenticationConfigurer> configurer) {
        configurer.customize(getConfigurer(ClientAuthenticationConfigurer.class));
        return this;
    }

    public final Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>,
            SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> getConfigurers() {
        return Collections.unmodifiableMap(configurers);
    }

    private Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>,
            SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> createConfigurers() {

        Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>,
                SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> configurers = new LinkedHashMap<>();

        configurers.put(ClientAuthenticationConfigurer.class, new ClientAuthenticationConfigurer());
        configurers.put(AuthorizationEndpointConfigurer.class, new AuthorizationEndpointConfigurer());
        configurers.put(TokenEndpointConfigurer.class, new ClientAuthenticationConfigurer());
        return configurers;
    }

    public final RequestMatcher getRequestMatcher() {
        if (requestMatcher == null) {
            requestMatcher = new OrRequestMatcher(
                    new AntPathRequestMatcher(serverConfig.getTokenEndpoint()),
                    new AntPathRequestMatcher(serverConfig.getIntrospectionEndpoint()),
                    new AntPathRequestMatcher(serverConfig.getRevocationEndpoint())
            );
        }

        return requestMatcher;
    }

    @SuppressWarnings("unchecked")
    public final <T extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> T getConfigurer(Class<T> clazz) {
        return (T) configurers.get(clazz);
    }
}
