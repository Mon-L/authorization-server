package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.ClientService;
import cn.zcn.authorization.server.ServerConfig;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 服务配置类，包含服务所有可配置的 configurer
 */
public class ServerSecurityConfigurer {

    private final Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>,
            SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> configurers = createConfigurers();

    private RequestMatcher requestMatcher;
    private ClientService clientService;
    private ServerConfig serverConfig;

    public final void init(HttpSecurity builder) {
        Assert.notNull(serverConfig, "ProviderConfig must not be null.");
        Assert.notNull(clientService, "ClientService must not be null.");

        builder.getSharedObjects().put(ClientService.class, clientService);
        builder.getSharedObjects().put(ServerConfig.class, serverConfig);
    }

    public ServerSecurityConfigurer clientService(ClientService clientService) {
        this.clientService = clientService;
        return this;
    }

    public ServerSecurityConfigurer providerConfig(ServerConfig serverConfig) {
        this.serverConfig = serverConfig;
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
        configurers.put(AuthorizationEndpointConfigurer.class, new ClientAuthenticationConfigurer());
        configurers.put(TokenEndpointConfigurer.class, new ClientAuthenticationConfigurer());
        return configurers;
    }

    public final RequestMatcher getRequestMatcher() {
        if (requestMatcher == null) {
            requestMatcher = new OrRequestMatcher(
            );
        }

        return requestMatcher;
    }

    @SuppressWarnings("unchecked")
    public final <T extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> T getConfigurer(Class<T> clazz) {
        return (T) configurers.get(clazz);
    }
}
