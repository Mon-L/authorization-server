package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.ClientService;
import cn.zcn.authorization.server.RequestMappingDetector;
import cn.zcn.authorization.server.RequestResolver;
import cn.zcn.authorization.server.endpoint.TokenEndpoint;
import cn.zcn.authorization.server.grant.TokenGranter;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * 令牌端点配置类
 */
public class TokenEndpointConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    @Override
    public void init(HttpSecurity builder) throws Exception {
    }

    @Override
    public void configure(HttpSecurity builder) {
        TokenEndpoint endpoint = builder.getSharedObject(TokenEndpoint.class);
        endpoint.setClientService(builder.getSharedObject(ClientService.class));
        endpoint.setRequestResolver(builder.getSharedObject(RequestResolver.class));
        endpoint.setTokenGranter(builder.getSharedObject(TokenGranter.class));

        builder.getSharedObject(RequestMappingDetector.class).detectHandlerMethods(TokenEndpoint.class, endpoint);
    }
}
