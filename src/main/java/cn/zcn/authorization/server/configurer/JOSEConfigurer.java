package cn.zcn.authorization.server.configurer;

import cn.zcn.authorization.server.jose.DefaultJWTDecrypter;
import cn.zcn.authorization.server.jose.DefaultJWTSigner;
import cn.zcn.authorization.server.jose.JWTDecrypter;
import cn.zcn.authorization.server.jose.JWTSigner;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

import java.util.List;

/**
 * 授权服务 JOSE 相关配置
 */
public class JOSEConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    /**
     * 用于授权服务加签、解密的密钥集合
     */
    private JWKSource<SecurityContext> jwkSource = new EmptyJwkSource();

    /**
     * 用于授权服务加签（如 id token 加签等）
     */
    private JWTSigner jwtSigner;

    /**
     * 用与授权服务解密(如 request object 解密等)
     */
    private JWTDecrypter jwtDecrypter;

    @Override
    public void init(HttpSecurity builder) throws Exception {
        builder.setSharedObject(JWTSigner.class, jwtSigner == null ? new DefaultJWTSigner(jwkSource) : jwtSigner);
        builder.setSharedObject(JWTDecrypter.class, jwtDecrypter == null ? new DefaultJWTDecrypter(jwkSource) : jwtDecrypter);
    }

    public JOSEConfigurer jwkSource(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
        return this;
    }

    public JOSEConfigurer jwtSigner(JWTSigner jwtSigner) {
        this.jwtSigner = jwtSigner;
        return this;
    }

    public JOSEConfigurer jwtDecrypter(JWTDecrypter jwtDecrypter) {
        this.jwtDecrypter = jwtDecrypter;
        return this;
    }

    private static class EmptyJwkSource implements JWKSource<SecurityContext> {
        @Override
        public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) throws KeySourceException {
            return null;
        }
    }
}
