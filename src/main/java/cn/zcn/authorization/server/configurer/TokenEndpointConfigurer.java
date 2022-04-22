package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.ClientService;
import cn.zcn.authorization.server.RequestMappingDetector;
import cn.zcn.authorization.server.RequestResolver;
import cn.zcn.authorization.server.ServerConfig;
import cn.zcn.authorization.server.endpoint.TokenEndpoint;
import cn.zcn.authorization.server.exception.ExceptionWriter;
import cn.zcn.authorization.server.grant.TokenGranter;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.util.Assert;

/**
 * 令牌端点功能配置，如令牌颁发<p>
 * 注册令牌端点到{@link org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping}
 */
public class TokenEndpointConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    @Override
    public void init(HttpSecurity builder) throws Exception {
    }

    @Override
    public void configure(HttpSecurity builder) {
        ServerConfig serverConfig = builder.getSharedObject(ServerConfig.class);
        TokenEndpoint endpoint = builder.getSharedObject(TokenEndpoint.class);
        Assert.notNull(endpoint, "AuthorizationEndpoint must not be null.");

        endpoint.setClientService(builder.getSharedObject(ClientService.class));
        endpoint.setRequestResolver(builder.getSharedObject(RequestResolver.class));
        endpoint.setTokenGranter(builder.getSharedObject(TokenGranter.class));
        endpoint.setExceptionWriter(builder.getSharedObject(ExceptionWriter.class));

        builder.getSharedObject(RequestMappingDetector.class)
                .detectHandlerMethods(
                        TokenEndpoint.class,
                        endpoint,
                        requestMappingInfo -> requestMappingInfo.paths(serverConfig.getTokenEndpoint())
                );
    }
}
