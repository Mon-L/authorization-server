package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerifierFactory;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

public class DefaultJWTSignerTest {

    private List<JWK> jwkList;

    private JWKSource<SecurityContext> jwkSource;

    private JWTSigner jwtSigner;

    private JWSVerifierFactory jwsVerifierFactory;

    @BeforeEach
    public void setUp() {
        this.jwkList = new ArrayList<>();
        this.jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(this.jwkList));
        this.jwtSigner = new DefaultJWTSigner(this.jwkSource);

        jwsVerifierFactory = new DefaultJWSVerifierFactory();
        jwsVerifierFactory.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
    }

    @Test
    public void initJWSEncoderWhenNullJWKSource() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new DefaultJWTSigner(null))
                .withMessage("jwkSource must not be null");
    }

    @Test
    public void testWhenSelectJWKThenJWKException() throws Exception {
        this.jwkSource = mock(JWKSource.class);
        this.jwtSigner = new DefaultJWTSigner(this.jwkSource);

        given(this.jwkSource.get(any(), any())).willThrow(new KeySourceException("key source error"));

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().build();

        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtSigner.sign(header, claims))
                .withMessageStartingWith("Failed to select jwk ");
    }

    @Test
    public void testWhenSelectEmptyJWKThenJWKException() {
        this.jwkSource = mock(JWKSource.class);
        this.jwtSigner = new DefaultJWTSigner(this.jwkSource);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().build();

        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtSigner.sign(header, claims))
                .withMessageStartingWith("Failed to select a jwk.");
    }

    @Test
    public void testWhenSelectJWKThenThrowMultipleJWK() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("1").generate();
        this.jwkList.add(key);
        this.jwkList.add(key);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256).keyID("1").build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().build();

        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtSigner.sign(header, claims))
                .withMessage("Found multiple jwk.");
    }

    @Test
    public void testWhenMismatchJwkKeyUsesThenThrowException() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("1").keyUse(KeyUse.ENCRYPTION).generate();
        this.jwkList.add(key);
        this.jwkList.add(key);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256).keyID("1").build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().build();

        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtSigner.sign(header, claims))
                .withMessage("Failed to select a jwk.");
    }

    @Test
    public void testWhenMismatchAlgThenThrowException() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("1").generate();
        this.jwkList.add(key);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("1").build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder().build();

        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtSigner.sign(header, claims))
                .withMessage("Failed to select a jwk.");
    }

    @Test
    public void signWithRSAKeyThenSuccess() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("1").keyUse(KeyUse.SIGNATURE).generate();
        this.jwkList.add(key);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256).keyID("1").build();
        JWTClaimsSet claims = new JWTClaimsSet
                .Builder()
                .jwtID("123")
                .issuer("https://localhost:8888")
                .claim("foo", "bar")
                .build();

        //sign
        SignedJWT signedJWT = jwtSigner.sign(header, claims);
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);

        //verify
        JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(signedJWT.getHeader(), key.toPublicKey());
        assertThat(jwsVerifier.verify(signedJWT.getHeader(), signedJWT.getSigningInput(), signedJWT.getSignature())).isTrue();
    }

    @Test
    public void signWhenNoKidThenSuccess() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("1").keyUse(KeyUse.SIGNATURE).generate();
        this.jwkList.add(key);

        //header hasn't kid.
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.PS256).build();
        JWTClaimsSet claims = new JWTClaimsSet
                .Builder()
                .jwtID("123")
                .issuer("https://localhost:8888")
                .claim("foo", "bar")
                .build();

        //sign
        SignedJWT signedJWT = jwtSigner.sign(header, claims);
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);
        assertThat(signedJWT.getHeader().getKeyID()).isEqualTo(key.getKeyID()); //check kid

        //verify
        JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(signedJWT.getHeader(), key.toPublicKey());
        assertThat(jwsVerifier.verify(signedJWT.getHeader(), signedJWT.getSigningInput(), signedJWT.getSignature())).isTrue();
    }

    @Test
    public void signWithECKeyThenSuccess() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_521)
                .keyID("1")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        this.jwkList.add(key);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES512).keyID("1").build();
        JWTClaimsSet claims = new JWTClaimsSet
                .Builder()
                .jwtID("123")
                .issuer("https://localhost:8888")
                .claim("foo", "bar")
                .build();

        //sign
        SignedJWT signedJWT = jwtSigner.sign(header, claims);
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);

        //verify
        JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(signedJWT.getHeader(), key.toPublicKey());
        assertThat(jwsVerifier.verify(signedJWT.getHeader(), signedJWT.getSigningInput(), signedJWT.getSignature())).isTrue();
    }

    @Test
    public void signWithOctetSequenceKeyThenSuccess() throws Exception {
        OctetSequenceKey key = new OctetSequenceKeyGenerator(512)
                .keyID("1")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        this.jwkList.add(key);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS512).keyID("1").build();
        JWTClaimsSet claims = new JWTClaimsSet
                .Builder()
                .jwtID("123")
                .issuer("https://localhost:8888")
                .claim("foo", "bar")
                .build();

        //sign
        SignedJWT signedJWT = jwtSigner.sign(header, claims);
        assertThat(signedJWT.getState()).isEqualTo(JWSObject.State.SIGNED);

        //verify
        JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(signedJWT.getHeader(), key.toSecretKey());
        assertThat(jwsVerifier.verify(signedJWT.getHeader(), signedJWT.getSigningInput(), signedJWT.getSignature())).isTrue();
    }

    @Test
    public void signWithStringPayloadThenSuccess() throws Exception {
        OctetSequenceKey key = new OctetSequenceKeyGenerator(512)
                .keyID("1")
                .keyUse(KeyUse.SIGNATURE)
                .generate();
        this.jwkList.add(key);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS512).keyID("1").build();
        Payload payload = new Payload("123");

        //sign
        JWSObject jwsObject = jwtSigner.sign(header, payload);
        assertThat(jwsObject.getState()).isEqualTo(JWSObject.State.SIGNED);

        //verify
        JWSVerifier jwsVerifier = jwsVerifierFactory.createJWSVerifier(jwsObject.getHeader(), key.toSecretKey());
        assertThat(jwsVerifier.verify(jwsObject.getHeader(), jwsObject.getSigningInput(), jwsObject.getSignature())).isTrue();
    }
}
