package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.RequestMappingDetector;
import cn.zcn.authorization.server.ServerConfig;
import cn.zcn.authorization.server.TokenService;
import cn.zcn.authorization.server.endpoint.RevocationEndpoint;
import cn.zcn.authorization.server.exception.ExceptionWriter;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

public class RevocationEndpointConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private ServerConfig serverConfig;

    @Override
    public void init(HttpSecurity builder) {
        serverConfig = builder.getSharedObject(ServerConfig.class);
    }

    @Override
    public void configure(HttpSecurity builder) {
        RevocationEndpoint endpoint = builder.getSharedObject(RevocationEndpoint.class);
        endpoint.setExceptionWriter(builder.getSharedObject(ExceptionWriter.class));
        endpoint.setTokenService(builder.getSharedObject(TokenService.class));

        builder.getSharedObject(RequestMappingDetector.class)
                .detectHandlerMethods(
                        RevocationEndpoint.class,
                        endpoint,
                        requestMappingInfo -> requestMappingInfo.paths(serverConfig.getRevocationEndpoint())
                );
    }
}
