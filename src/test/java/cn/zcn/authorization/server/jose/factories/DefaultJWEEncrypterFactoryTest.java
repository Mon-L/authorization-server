package cn.zcn.authorization.server.jose.factories;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class DefaultJWEEncrypterFactoryTest {

    private JWEEncrypterFactory jweEncrypterFactory;

    @BeforeEach
    public void init() {
        jweEncrypterFactory = new DefaultJWEEncrypterFactory();
    }

    @Test
    public void testWithMismatchKeyThenThrowException() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).generate();

        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM)
                .keyID("1")
                .build();

        assertThatExceptionOfType(JWKException.class)
                .isThrownBy(() -> jweEncrypterFactory.createJWEEncrypter(header, rsaKey));
    }

    @Test
    public void testWithRSAAlg() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).generate();

        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                .keyID("1")
                .build();

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("123").build();

        EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);
        JWEEncrypter jweEncrypter = jweEncrypterFactory.createJWEEncrypter(header, rsaKey);
        encryptedJWT.encrypt(jweEncrypter);

        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);
    }

    @Test
    public void testWithECAlg() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).generate();

        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A128GCM)
                .keyID("1")
                .build();

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("123").build();

        EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);
        JWEEncrypter jweEncrypter = jweEncrypterFactory.createJWEEncrypter(header, ecKey);
        encryptedJWT.encrypt(jweEncrypter);

        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);
    }

    @Test
    public void testWithDirAlg() throws Exception {
        OctetSequenceKey key = new OctetSequenceKeyGenerator(128).generate();

        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM)
                .keyID("1")
                .build();

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("123").build();

        EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);
        JWEEncrypter jweEncrypter = jweEncrypterFactory.createJWEEncrypter(header, key);
        encryptedJWT.encrypt(jweEncrypter);

        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);
    }

    @Test
    public void testWithAESAlg() throws Exception {
        OctetSequenceKey key = new OctetSequenceKeyGenerator(128).generate();

        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM)
                .keyID("1")
                .build();

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("123").build();

        EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);
        JWEEncrypter jweEncrypter = jweEncrypterFactory.createJWEEncrypter(header, key);
        encryptedJWT.encrypt(jweEncrypter);

        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);
    }

    @Test
    public void testWithPasswordBaseAlg() throws Exception {
        OctetSequenceKey key = new OctetSequenceKeyGenerator(256).generate();

        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.PBES2_HS256_A128KW, EncryptionMethod.A128GCM)
                .keyID("1")
                .build();

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("123").build();

        EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);
        JWEEncrypter jweEncrypter = jweEncrypterFactory.createJWEEncrypter(header, key);
        encryptedJWT.encrypt(jweEncrypter);

        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);
    }
}
