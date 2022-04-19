package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.ClientAuthMethod;
import cn.zcn.authorization.server.ClientService;
import cn.zcn.authorization.server.ServerConfig;
import cn.zcn.authorization.server.authentication.extractor.AuthenticationExtractor;
import cn.zcn.authorization.server.authentication.extractor.ClientAssertionExtractor;
import cn.zcn.authorization.server.authentication.extractor.ClientSecretBasicExtractor;
import cn.zcn.authorization.server.authentication.extractor.ClientSecretPostExtractor;
import cn.zcn.authorization.server.authentication.provider.ClientSecretAuthenticationProvider;
import cn.zcn.authorization.server.authentication.provider.JWTAssertionAuthenticationProvider;
import cn.zcn.authorization.server.exception.ExceptionWriter;
import cn.zcn.authorization.server.filter.ClientAuthenticationFilter;
import cn.zcn.authorization.server.jose.ClientJOSEService;
import com.google.common.collect.Sets;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * 客户端身份验证配置类。用于配置客户端身份校验的策略。
 * 该配置类会往{@link HttpSecurity}中添加一个{@link ClientAuthenticationFilter}，用于拦截需要客户端身份校验的端点。
 */
public class ClientAuthenticationConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private RequestMatcher requestMatcher;

    private List<AuthenticationProvider> authenticationProviders;

    private List<AuthenticationExtractor> authenticationExtractors;

    private AuthenticationSuccessHandler authenticationSuccessHandler;

    private AuthenticationFailureHandler authenticationFailureHandler;

    /**
     * 允许的客户端认证方式
     */
    private final Set<ClientAuthMethod> allowedClientAuthMethods = Sets.newHashSet(
            ClientAuthMethod.SECRET_BASIC, ClientAuthMethod.SECRET_POST, ClientAuthMethod.SECRET_JWT,
            ClientAuthMethod.PRIVATE_KEY);

    @Override
    public void init(HttpSecurity builder) throws Exception {
        ClientService clientService = builder.getSharedObject(ClientService.class);
        ServerConfig serverConfig = builder.getSharedObject(ServerConfig.class);
        ExceptionWriter exceptionWriter = builder.getSharedObject(ExceptionWriter.class);

        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher(serverConfig.getTokenEndpoint()),
                new AntPathRequestMatcher(serverConfig.getIntrospectionEndpoint()),
                new AntPathRequestMatcher(serverConfig.getRevocationEndpoint())
        );

        if (this.authenticationSuccessHandler == null) {
            this.authenticationSuccessHandler = (request, response, authentication) -> {
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(authentication);
                SecurityContextHolder.setContext(securityContext);
            };
        }

        if (this.authenticationFailureHandler == null) {
            this.authenticationFailureHandler = (request, response, e) -> {
                SecurityContextHolder.clearContext();

                exceptionWriter.write(e, new ServletWebRequest(request, response));
            };
        }

        authenticationExtractors = new ArrayList<>();
        if (allowedClientAuthMethods.contains(ClientAuthMethod.SECRET_BASIC)) {
            authenticationExtractors.add(new ClientSecretBasicExtractor());
        }

        if (allowedClientAuthMethods.contains(ClientAuthMethod.SECRET_POST)) {
            authenticationExtractors.add(new ClientSecretPostExtractor());
        }

        if (allowedClientAuthMethods.contains(ClientAuthMethod.SECRET_POST) || allowedClientAuthMethods.contains(ClientAuthMethod.PRIVATE_KEY)) {
            authenticationExtractors.add(new ClientAssertionExtractor());
        }

        authenticationProviders = new ArrayList<>();
        if (allowedClientAuthMethods.contains(ClientAuthMethod.SECRET_BASIC) || allowedClientAuthMethods.contains(ClientAuthMethod.SECRET_POST)) {
            authenticationProviders.add(new ClientSecretAuthenticationProvider(clientService));
        }

        if (allowedClientAuthMethods.contains(ClientAuthMethod.SECRET_POST) || allowedClientAuthMethods.contains(ClientAuthMethod.PRIVATE_KEY)) {
            authenticationProviders.add(new JWTAssertionAuthenticationProvider(
                    serverConfig,
                    clientService,
                    builder.getSharedObject(ClientJOSEService.class)
            ));
        }
    }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        ProviderManager providerManager = new ProviderManager(authenticationProviders);

        ClientAuthenticationFilter filter = new ClientAuthenticationFilter(
                requestMatcher, authenticationExtractors, providerManager,
                authenticationSuccessHandler, authenticationFailureHandler
        );

        //添加客户端验证的 filter 到 HttpSecurity
        builder.addFilterAfter(postProcess(filter), AbstractPreAuthenticatedProcessingFilter.class);
    }

    public ClientAuthenticationConfigurer allowedClientAuthMethods(ClientAuthMethod... clientAuthMethods) {
        allowedClientAuthMethods.clear();

        allowedClientAuthMethods.addAll(Arrays.asList(clientAuthMethods));
        return this;
    }

    public ClientAuthenticationConfigurer authenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        this.authenticationFailureHandler = authenticationFailureHandler;
        return this;
    }

    public ClientAuthenticationConfigurer authenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        return this;
    }
}
