package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.util.Assert;

import java.security.Key;
import java.security.Provider;
import java.util.List;

public class DefaultJWTVerifier implements JWTVerifier {

    private final JWSVerifierFactory jwsVerifierFactory;

    /**
     * 验签所需的公钥集合
     */
    private final JWKSource<SecurityContext> jwkSource;

    public DefaultJWTVerifier(JWKSource<SecurityContext> jwkSource) {
        this(jwkSource, BouncyCastleProviderSingleton.getInstance());
    }

    public DefaultJWTVerifier(JWKSource<SecurityContext> jwkSource, Provider provider) {
        Assert.notNull(jwkSource, "jwkSource must not be null");
        Assert.notNull(provider, "provider must not be null");

        this.jwkSource = jwkSource;
        this.jwsVerifierFactory = new DefaultJWSVerifierFactory();
        this.jwsVerifierFactory.getJCAContext().setProvider(provider);
    }

    @Override
    public boolean verify(JWSObject jws) throws JOSERuntimeException {
        JWK jwk = selectJWK(jws.getHeader());

        try {
            Key key = jwk instanceof RSAKey ? jwk.toRSAKey().toPublicKey() :
                    jwk instanceof ECKey ? jwk.toECKey().toPublicKey() :
                            jwk instanceof OctetSequenceKey ? jwk.toOctetSequenceKey().toSecretKey() : null;

            if (key == null) {
                throw new JOSERuntimeException("Unsupported jwk type(Should be RSAKey 、 ECKey 、 OctetSequenceKey).");
            }

            JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(jws.getHeader(), key);
            return jws.verify(jwsVerifier);
        } catch (JOSEException e) {
            throw new JOSERuntimeException(e.getMessage(), e);
        }
    }

    private JWK selectJWK(JWSHeader header) {
        List<JWK> jwks;

        try {
            JWKMatcher jwkMatcher = JWKMatcher.forJWSHeader(header);
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
