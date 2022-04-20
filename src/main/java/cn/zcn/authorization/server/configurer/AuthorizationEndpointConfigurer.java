package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.endpoint.AuthorizationEndpoint;
import cn.zcn.authorization.server.grant.TokenGranter;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.util.Assert;

/**
 * 配置授权端点，如授权码的颁发、用户同意、访问令牌颁发<p>
 * 注册授权端点到{@link org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping}
 */
public class AuthorizationEndpointConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private ApprovalService approvalService;

    private AuthorizationCodeService authorizationCodeService;

    @Override
    public void init(HttpSecurity builder) throws Exception {
    }

    @Override
    public void configure(HttpSecurity builder) {
        ServerConfig serverConfig = builder.getSharedObject(ServerConfig.class);
        AuthorizationEndpoint endpoint = builder.getSharedObject(AuthorizationEndpoint.class);
        Assert.notNull(endpoint, "AuthorizationEndpoint must not be null.");

        endpoint.setAuthorizationCodeService(authorizationCodeService);
        endpoint.setApprovalService(approvalService);
        endpoint.setTokenGranter(builder.getSharedObject(TokenGranter.class));
        endpoint.setClientService(builder.getSharedObject(ClientService.class));
        endpoint.setRequestResolver(builder.getSharedObject(RequestResolver.class));

        RequestMappingDetector requestMappingDetector = builder.getSharedObject(RequestMappingDetector.class);
        Assert.notNull(requestMappingDetector, "RequestMappingDetector must not be null.");
        requestMappingDetector.detectHandlerMethods(
                AuthorizationEndpoint.class,
                endpoint,
                requestMappingInfo -> requestMappingInfo.paths(serverConfig.getAuthorizationEndpoint())
        );
    }

    public AuthorizationEndpointConfigurer approvalService(ApprovalService approvalService) {
        this.approvalService = approvalService;
        return this;
    }

    public AuthorizationEndpointConfigurer authorizationCodeService(AuthorizationCodeService authorizationCodeService) {
        this.authorizationCodeService = authorizationCodeService;
        return this;
    }

    public AuthorizationCodeService getAuthorizationCodeService() {
        return authorizationCodeService;
    }

    public ApprovalService getApprovalService() {
        return approvalService;
    }
}
