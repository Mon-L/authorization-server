package cn.zcn.authorization.server.authentication.provider;


import cn.zcn.authorization.server.authentication.JWTAssertionAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * 验证 Client Assertion 是否有效
 * 参考规范: https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
 */
public class JWTAssertionAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return null;
    }


    @Override
    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(JWTAssertionAuthenticationToken.class);
    }
}
