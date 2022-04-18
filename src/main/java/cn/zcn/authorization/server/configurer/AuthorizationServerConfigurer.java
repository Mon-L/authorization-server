package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.exception.DefaultExceptionWriter;
import cn.zcn.authorization.server.exception.ExceptionWriter;
import cn.zcn.authorization.server.grant.*;
import cn.zcn.authorization.server.jose.*;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.authentication.AuthenticationManager;
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
import java.util.List;
import java.util.Map;

/**
 * 服务配置类，包含授权服务所有可配置的类{@link SecurityConfigurerAdapter}
 */
public class AuthorizationServerConfigurer {

    private final Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>,
            SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> configurers = createConfigurers();

    private RequestMatcher requestMatcher;

    private ClientService clientService;

    private RequestResolver requestResolver;

    private TokenGranter tokenGranter;

    private TokenService tokenService;

    /**
     * 用于授权服务签名、解密的密钥集合
     */
    private JWKSource<SecurityContext> jwkSource = new EmptyJwkSource();

    /**
     * 用于授权服务签名，如 id token 签名等
     */
    private JWTSigner jwtSigner;

    /**
     * 用于授权服务解密，如 request object 解密等
     */
    private JWTDecrypter jwtDecrypter;

    /**
     * 用于验证客户端请求的签名以及加密发送给客户端的响应信息
     */
    private ClientJOSEService clientJOSEService;

    /**
     * 用于用户认证，当需要使用 password 模式的时候必须设置。
     */
    private AuthenticationManager userAuthenticationManager;

    private ServerConfig serverConfig = new ServerConfig.Builder().build();

    private ExceptionWriter exceptionWriter = new DefaultExceptionWriter();

    public final void init(HttpSecurity builder) {
        Assert.notNull(clientService, "ClientService must not be null.");

        // 配置缺省实现类
        if (jwtSigner == null) {
            jwtSigner = new DefaultJWTSigner(jwkSource);
        }

        if (jwtDecrypter == null) {
            jwtDecrypter = new DefaultJWTDecrypter(jwkSource);
        }

        if (clientJOSEService == null) {
            clientJOSEService = new DefaultClientJOSEService();
        }

        if (requestResolver == null) {
            requestResolver = new DefaultRequestResolver();
        }

        if (tokenGranter == null) {
            CompositeTokenGranter compositeTokenGranter = new CompositeTokenGranter();
            compositeTokenGranter.addTokenGranter(new AuthorizationCodeTokenGranter(
                    getConfigurer(AuthorizationEndpointConfigurer.class).getAuthorizationCodeService(), tokenService));
            compositeTokenGranter.addTokenGranter(new ClientCredentialsTokenGranter(tokenService));
            compositeTokenGranter.addTokenGranter(new ImplicitTokenGranter(tokenService));
            compositeTokenGranter.addTokenGranter(new RefreshTokenGranter(tokenService));

            if (userAuthenticationManager != null) {
                compositeTokenGranter.addTokenGranter(new ResourceOwnerPasswordTokenGranter(tokenService, userAuthenticationManager));
            }

            tokenGranter = compositeTokenGranter;
        }

        //将需要共享的配置添加到 shared object 中
        builder.setSharedObject(JWTSigner.class, jwtSigner);
        builder.setSharedObject(JWTDecrypter.class, jwtDecrypter);
        builder.setSharedObject(ClientJOSEService.class, clientJOSEService);
        builder.setSharedObject(ClientService.class, clientService);
        builder.setSharedObject(ServerConfig.class, serverConfig);
        builder.setSharedObject(ExceptionWriter.class, exceptionWriter);
        builder.setSharedObject(RequestResolver.class, requestResolver);
        builder.setSharedObject(TokenGranter.class, tokenGranter);
    }

    public AuthorizationServerConfigurer serverConfig(ServerConfig serverConfig) {
        this.serverConfig = serverConfig;
        return this;
    }

    public AuthorizationServerConfigurer clientService(ClientService clientService) {
        this.clientService = clientService;
        return this;
    }

    public AuthorizationServerConfigurer requestResolver(RequestResolver requestResolver) {
        this.requestResolver = requestResolver;
        return this;
    }

    public AuthorizationServerConfigurer exceptionWriter(ExceptionWriter exceptionWriter) {
        this.exceptionWriter = exceptionWriter;
        return this;
    }

    public AuthorizationServerConfigurer tokenGranter(TokenGranter tokenGranter) {
        this.tokenGranter = tokenGranter;
        return this;
    }

    public AuthorizationServerConfigurer tokenService(TokenService tokenService) {
        this.tokenService = tokenService;
        return this;
    }

    public AuthorizationServerConfigurer jwkSource(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
        return this;
    }

    public AuthorizationServerConfigurer jwtSigner(JWTSigner jwtSigner) {
        this.jwtSigner = jwtSigner;
        return this;
    }

    public AuthorizationServerConfigurer jwtDecrypter(JWTDecrypter jwtDecrypter) {
        this.jwtDecrypter = jwtDecrypter;
        return this;
    }

    public AuthorizationServerConfigurer clientJOSEService(ClientJOSEService clientJOSEService) {
        this.clientJOSEService = clientJOSEService;
        return this;
    }

    public AuthorizationServerConfigurer userAuthenticationManager(AuthenticationManager authenticationManager) {
        this.userAuthenticationManager = userAuthenticationManager;
        return this;
    }

    public AuthorizationServerConfigurer authorizationEndpoint(Customizer<AuthorizationEndpointConfigurer> configurer) {
        configurer.customize(getConfigurer(AuthorizationEndpointConfigurer.class));
        return this;
    }

    public AuthorizationServerConfigurer tokenEndpoint(Customizer<TokenEndpointConfigurer> configurer) {
        configurer.customize(getConfigurer(TokenEndpointConfigurer.class));
        return this;
    }

    public AuthorizationServerConfigurer clientAuthentication(Customizer<ClientAuthenticationConfigurer> configurer) {
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
        configurers.put(TokenEndpointConfigurer.class, new TokenEndpointConfigurer());
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

    private static class EmptyJwkSource implements JWKSource<SecurityContext> {
        @Override
        public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
            return null;
        }
    }
}
