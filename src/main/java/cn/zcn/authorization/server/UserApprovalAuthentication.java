package cn.zcn.authorization.server;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;

/**
 * 授权码模式下的用户同意认证信息。
 * <p>
 * 授权码模式流程：
 * 第一阶段是用户登录并授权客户端访问其资源，然后授权服务器颁发授权码给客户端
 * 第二阶段是客户端使用授权码兑换访问令牌
 * <p>
 * {@link UserApprovalAuthentication} 封装的就是第一阶段的用户同意及授权请求
 */
public class UserApprovalAuthentication extends AbstractAuthenticationToken {

    private final AuthorizationRequest authorizationRequest;
    private final Authentication userAuthentication;

    public UserApprovalAuthentication(@NonNull AuthorizationRequest authorizationRequest, @NonNull Authentication userAuthentication) {
        super(userAuthentication.getAuthorities());

        this.authorizationRequest = authorizationRequest;
        this.userAuthentication = userAuthentication;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return userAuthentication;
    }

    @Override
    public boolean isAuthenticated() {
        return this.authorizationRequest.isApproved() && this.userAuthentication.isAuthenticated();
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        if (CredentialsContainer.class.isAssignableFrom(userAuthentication.getClass())) {
            ((CredentialsContainer) userAuthentication).eraseCredentials();
        }
    }

    public AuthorizationRequest getAuthorizationRequest() {
        return authorizationRequest;
    }

    public Authentication getUserAuthentication() {
        return userAuthentication;
    }
}
