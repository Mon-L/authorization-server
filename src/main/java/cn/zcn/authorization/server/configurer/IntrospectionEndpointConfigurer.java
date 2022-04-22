package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.endpoint.IntrospectionEndpoint;
import cn.zcn.authorization.server.exception.ExceptionWriter;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

public class IntrospectionEndpointConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private TokenConverter tokenConverter;
    private ServerConfig serverConfig;

    @Override
    public void init(HttpSecurity builder) {
        serverConfig = builder.getSharedObject(ServerConfig.class);

        if (tokenConverter == null) {
            tokenConverter = new DefaultTokenConverter(serverConfig);
        }
    }

    @Override
    public void configure(HttpSecurity builder) {
        IntrospectionEndpoint endpoint = builder.getSharedObject(IntrospectionEndpoint.class);
        endpoint.setTokenConverter(tokenConverter);

        endpoint.setExceptionWriter(builder.getSharedObject(ExceptionWriter.class));
        endpoint.setTokenService(builder.getSharedObject(TokenService.class));

        builder.getSharedObject(RequestMappingDetector.class)
                .detectHandlerMethods(
                        IntrospectionEndpoint.class,
                        endpoint,
                        requestMappingInfo -> requestMappingInfo.paths(serverConfig.getIntrospectionEndpoint())
                );
    }

    public IntrospectionEndpointConfigurer tokenConverter(TokenConverter tokenConverter) {
        this.tokenConverter = tokenConverter;
        return this;
    }
}
