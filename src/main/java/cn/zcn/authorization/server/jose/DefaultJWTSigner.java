package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.security.Provider;
import java.util.List;

public class DefaultJWTSigner implements JWTSigner {

    private final JWSSignerFactory jwsSignerFactory;
    private final JWKSource<SecurityContext> jwkSource;

    public DefaultJWTSigner(JWKSource<SecurityContext> jwkSource) {
        this(jwkSource, BouncyCastleProviderSingleton.getInstance());
    }

    public DefaultJWTSigner(JWKSource<SecurityContext> jwkSource, Provider provider) {
        Assert.notNull(jwkSource, "jwkSource must not be null");
        Assert.notNull(provider, "provider must not be null");
        
        this.jwkSource = jwkSource;
        this.jwsSignerFactory = new DefaultJWSSignerFactory();
        this.jwsSignerFactory.getJCAContext().setProvider(provider);
    }

    @Override
    public JWSObject sign(JWSHeader header, Payload payload) throws JOSERuntimeException {
        JWK jwk = selectJwk(header);

        header = addKeyIdIfNecessary(header, jwk);

        try {
            JWSSigner jwsSigner = jwsSignerFactory.createJWSSigner(jwk);

            JWSObject jwsObject = new JWSObject(header, payload);
            jwsObject.sign(jwsSigner);
            return jwsObject;
        } catch (JOSEException e) {
            throw new JOSERuntimeException("Failed to sign jwt " + e.getMessage(), e);
        }
    }

    @Override
    public SignedJWT sign(JWSHeader header, JWTClaimsSet claimsSet) throws JOSERuntimeException {
        JWK jwk = selectJwk(header);

        header = addKeyIdIfNecessary(header, jwk);

        try {
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            JWSSigner jwsSigner = jwsSignerFactory.createJWSSigner(jwk);
            signedJWT.sign(jwsSigner);
            return signedJWT;
        } catch (JOSEException e) {
            throw new JOSERuntimeException("Failed to sign jwt " + e.getMessage(), e);
        }
    }

    private JWSHeader addKeyIdIfNecessary(JWSHeader header, JWK jwk) {
        if (StringUtils.hasText(header.getKeyID()) && header.getX509CertSHA256Thumbprint() != null) {
            return header;
        }

        if (!StringUtils.hasText(jwk.getKeyID()) && jwk.getX509CertSHA256Thumbprint() == null) {
            return header;
        }

        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(header);
        if (!StringUtils.hasText(header.getKeyID()) && StringUtils.hasText(jwk.getKeyID())) {
            headerBuilder.keyID(jwk.getKeyID());
        }

        if (header.getX509CertSHA256Thumbprint() == null && jwk.getX509CertSHA256Thumbprint() != null) {
            headerBuilder.x509CertSHA256Thumbprint(jwk.getX509CertSHA256Thumbprint());
        }

        return headerBuilder.build();
    }

    private JWK selectJwk(JWSHeader header) {
        List<JWK> jwks = null;
        try {
            JWKMatcher jwkMatcher = JWKMatcher.forJWSHeader(header);

            if (jwkMatcher != null) {
                JWKSelector jwkSelector = new JWKSelector(jwkMatcher);
                jwks = this.jwkSource.get(jwkSelector, null);
            }
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
