package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWEDecrypterFactory;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.util.Assert;

import java.security.Key;
import java.security.Provider;
import java.util.List;

public class DefaultJWTDecrypter implements JWTDecrypter {

    /**
     * 解密需要使用的私钥集合
     */
    private final JWKSource<SecurityContext> jwkSource;

    private final JWEDecrypterFactory jweDecrypterFactory;

    public DefaultJWTDecrypter(JWKSource<SecurityContext> jwkSource) {
        this(jwkSource, BouncyCastleProviderSingleton.getInstance());
    }

    public DefaultJWTDecrypter(JWKSource<SecurityContext> jwkSource, Provider provider) {
        Assert.notNull(jwkSource, "jwkSource must not be null");
        Assert.notNull(provider, "provider must not be null");

        this.jwkSource = jwkSource;
        this.jweDecrypterFactory = new DefaultJWEDecrypterFactory();
        this.jweDecrypterFactory.getJCAContext().setProvider(provider);
    }

    @Override
    public void decrypt(JWEObject jwe) throws JOSERuntimeException {
        JWK jwk = selectJWK(jwe.getHeader());

        if (!jwk.isPrivate()) {
            throw new JOSERuntimeException("Must be a private key.");
        }

        try {
            Key key = jwk instanceof RSAKey ? jwk.toRSAKey().toPrivateKey() :
                    jwk instanceof ECKey ? jwk.toECKey().toPrivateKey() :
                            jwk instanceof OctetSequenceKey ? jwk.toOctetSequenceKey().toSecretKey() : null;

            if (key == null) {
                throw new JOSERuntimeException("Unsupported jwk type(Should be RSAKey 、 ECKey 、 OctetSequenceKey).");
            }

            JWEDecrypter jweDecrypter = jweDecrypterFactory.createJWEDecrypter(jwe.getHeader(), key);
            jwe.decrypt(jweDecrypter);
        } catch (JOSEException e) {
            throw new JOSERuntimeException(e.getMessage(), e);
        }
    }

    private JWK selectJWK(JWEHeader header) {
        List<JWK> jwks;

        try {
            JWKMatcher jwkMatcher = JWKMatcher.forJWEHeader(header);
            JWKSelector jwkSelector = new JWKSelector(jwkMatcher);
            jwks = this.jwkSource.get(jwkSelector, null);
        } catch (KeySourceException e) {
            throw new JOSERuntimeException("Failed to select jwk " + e.getMessage(), e);
        }

        if (jwks == null || jwks.isEmpty()) {
            throw new JOSERuntimeException("Failed to select a jwk.");
        }

        if (jwks.size() > 1) {
            throw new JOSERuntimeException("Found multiple jwk.");
        }

        return jwks.get(0);
    }
}
