package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.Client;
import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import org.springframework.util.StringUtils;

public class DefaultClientJOSEService implements ClientJOSEService {

    private static final String CLIENT_SECRET_KEY = "client-secret-key";

    @Override
    public JWTVerifier getVerifier(Client client, JWSAlgorithm alg) throws JOSERuntimeException {
        JWKSource<SecurityContext> jwkSource;
        if (JWSAlgorithm.Family.HMAC_SHA.contains(alg)) {

            if (!StringUtils.hasText(client.getClientSecret())) {
                throw new JOSERuntimeException("Failed to covert empty client secret to jwk.");
            }

            JWK jwk = new OctetSequenceKey.Builder(Base64URL.encode(client.getClientSecret()))
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(CLIENT_SECRET_KEY)
                    .build();

            jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));

        } else if (JWSAlgorithm.Family.RSA.contains(alg)
                || JWSAlgorithm.Family.EC.contains(alg)
                || JWSAlgorithm.Family.ED.contains(alg)) {

            jwkSource = new ImmutableJWKSet<>(client.getJwks());

        } else {
            throw new JOSERuntimeException("Unsupported jws algorithm :" + alg.getName());
        }

        return new DefaultJWTVerifier(jwkSource);
    }

    @Override
    public JWTEncrypter getEncrypter(Client client) throws JOSERuntimeException {
        return new DefaultJWTEncrypter(new ImmutableJWKSet<>(client.getJwks()));
    }
}
