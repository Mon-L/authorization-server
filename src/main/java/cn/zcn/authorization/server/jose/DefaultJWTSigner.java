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

    /**
     * 加签所需的私钥集合
     */
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

        header = addKeyIdIfNecessary(header, jwk.getKeyID());

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

        header = addKeyIdIfNecessary(header, jwk.getKeyID());

        try {
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            JWSSigner jwsSigner = jwsSignerFactory.createJWSSigner(jwk);
            signedJWT.sign(jwsSigner);
            return signedJWT;
        } catch (JOSEException e) {
            throw new JOSERuntimeException("Failed to sign jwt " + e.getMessage(), e);
        }
    }

    /**
     * 当符合以下情况时，为 JWSHeader 添加 kid 或 公钥证书指纹
     * 1. JWSHeader 不含 kid
     * 2. 入参 kid 不为 null 或 空字符串
     *
     * @param header JWE Header
     * @param kid    JWK kid
     * @return 返回添加了 kid 的新的 {@link JWSHeader}
     */
    private JWSHeader addKeyIdIfNecessary(JWSHeader header, String kid) {
        if (!StringUtils.hasText(header.getKeyID()) && StringUtils.hasText(kid)) {
            header = new JWSHeader.Builder(header).keyID(kid).build();
        }

        return header;
    }

    private JWK selectJwk(JWSHeader header) {
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
