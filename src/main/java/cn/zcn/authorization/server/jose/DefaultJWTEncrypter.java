package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import cn.zcn.authorization.server.jose.factories.DefaultJWEEncrypterFactory;
import cn.zcn.authorization.server.jose.factories.JWEEncrypterFactory;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.Provider;
import java.util.List;

/**
 * encrypt jwe
 */
public class DefaultJWTEncrypter implements JWTEncrypter {

    private final JWKSource<SecurityContext> jwkSource;
    private final JWEEncrypterFactory jweEncrypterFactory;

    public DefaultJWTEncrypter(JWKSource<SecurityContext> jwkSource) {
        this(jwkSource, BouncyCastleProviderSingleton.getInstance());
    }

    public DefaultJWTEncrypter(JWKSource<SecurityContext> jwkSource, Provider provider) {
        Assert.notNull(jwkSource, "jwkSource must not be null");
        Assert.notNull(provider, "provider must not be null");
        
        this.jwkSource = jwkSource;
        this.jweEncrypterFactory = new DefaultJWEEncrypterFactory();
        this.jweEncrypterFactory.getJCAContext().setProvider(provider);
    }

    @Override
    public EncryptedJWT encrypt(JWEHeader header, JWTClaimsSet claimsSet) throws JOSERuntimeException {
        JWK jwk = selectJWK(header);

        try {
            header = addKeyIdIfNecessary(header, jwk.getKeyID());
            EncryptedJWT encryptedJWT = new EncryptedJWT(header, claimsSet);
            JWEEncrypter jweEncrypter = jweEncrypterFactory.createJWEEncrypter(header, jwk);
            encryptedJWT.encrypt(jweEncrypter);

            return encryptedJWT;
        } catch (JOSEException e) {
            throw new JOSERuntimeException("Failed to encrypt jwt." + e.getMessage(), e);
        }
    }

    @Override
    public JWEObject encrypt(JWEHeader header, Payload payload) throws JOSERuntimeException {
        JWK jwk = selectJWK(header);

        try {
            header = addKeyIdIfNecessary(header, jwk.getKeyID());

            JWEObject jweObject = new JWEObject(header, payload);
            JWEEncrypter jweEncrypter = jweEncrypterFactory.createJWEEncrypter(header, jwk);
            jweObject.encrypt(jweEncrypter);

            return jweObject;
        } catch (JOSEException e) {
            throw new JOSERuntimeException("Failed to encrypt jwt." + e.getMessage(), e);
        }
    }

    private JWEHeader addKeyIdIfNecessary(JWEHeader header, String kid) {
        if (StringUtils.hasText(header.getKeyID())) {
            return header;
        }

        if (!StringUtils.hasText(header.getKeyID()) && StringUtils.hasText(kid)) {
            header = new JWEHeader.Builder(header).keyID(kid).build();
        }

        return header;
    }

    private JWK selectJWK(JWEHeader header) {
        List<JWK> jwks = null;

        try {
            JWKMatcher jwkMatcher = JWKMatcher.forJWEHeader(header);

            if (jwkMatcher != null) {
                JWKSelector jwkSelector = new JWKSelector(jwkMatcher);
                jwks = this.jwkSource.get(jwkSelector, null);
            }
        } catch (KeySourceException e) {
            throw new JOSERuntimeException("Failed to select jwk." + e.getMessage(), e);
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
