package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.*;
import cn.zcn.authorization.server.endpoint.AuthorizationEndpoint;
import cn.zcn.authorization.server.grant.TokenGranter;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * 授权端点配置类
 */
public class AuthorizationEndpointConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private ApprovalService approvalService;

    private AuthorizationCodeService authorizationCodeService;

    @Override
    public void init(HttpSecurity builder) throws Exception {
    }

    @Override
    public void configure(HttpSecurity builder) {
        AuthorizationEndpoint endpoint = builder.getSharedObject(AuthorizationEndpoint.class);

        endpoint.setAuthorizationCodeService(authorizationCodeService);
        endpoint.setApprovalService(approvalService);

        endpoint.setTokenGranter(builder.getSharedObject(TokenGranter.class));
        endpoint.setClientService(builder.getSharedObject(ClientService.class));
        endpoint.setRequestResolver(builder.getSharedObject(RequestResolver.class));

        builder.getSharedObject(RequestMappingDetector.class).detectHandlerMethods(AuthorizationEndpoint.class, endpoint);
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
