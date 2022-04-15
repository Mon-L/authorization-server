package cn.zcn.authorization.server.jose;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

public class DefaultJWTVerifierTest {

    private JWTVerifier jwtVerifier;

    private List<JWK> jwkList;

    private JWKSource<SecurityContext> jwkSource;

    @BeforeEach
    public void init() {
        this.jwkList = new ArrayList<>();
        this.jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(this.jwkList));

        jwtVerifier = new DefaultJWTVerifier(jwkSource);
    }

    @Test
    public void testVerifyWithRSA() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("1").keyUse(KeyUse.SIGNATURE).generate();
        jwkList.add(rsaKey);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256).keyID("1").build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("a").build();

        //sign
        SignedJWT signedJWT = new DefaultJWTSigner(jwkSource).sign(header, jwtClaimsSet);

        //verify
        jwtVerifier.verify(signedJWT);
    }
}
