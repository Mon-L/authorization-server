package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

public class DefaultJWTDecrypterTest {

    private List<JWK> jwkList;

    private JWTDecrypter jwtDecrypter;

    private JWKSource<SecurityContext> jwkSource;

    private String encryptJweWithRSAKey(RSAKey key, JWEHeader header, JWTClaimsSet jwtClaimsSet) throws JOSEException {
        EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);
        RSAEncrypter encrypter = new RSAEncrypter(key);
        encryptedJWT.encrypt(encrypter);
        return encryptedJWT.serialize();
    }

    private String encryptJweWithECKey(ECKey key, JWEHeader header, JWTClaimsSet jwtClaimsSet) throws JOSEException {
        EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);
        ECDHEncrypter encrypter = new ECDHEncrypter(key);
        encryptedJWT.encrypt(encrypter);
        return encryptedJWT.serialize();
    }

    private String encryptJweWithOctetSequenceKey(OctetSequenceKey key, JWEHeader header, JWTClaimsSet jwtClaimsSet) throws JOSEException {
        EncryptedJWT encryptedJWT = new EncryptedJWT(header, jwtClaimsSet);
        AESEncrypter encrypter = new AESEncrypter(key);
        encryptedJWT.encrypt(encrypter);
        return encryptedJWT.serialize();
    }

    @BeforeEach
    public void init() {
        this.jwkList = new ArrayList<>();
        this.jwkSource = (jwkSelector, context) -> jwkSelector.select(new JWKSet(jwkList));
        this.jwtDecrypter = new DefaultJWTDecrypter(jwkSource);
    }

    @Test
    public void initWhenNullJWKSourceThenThrowException() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new DefaultJWTDecrypter(null));
    }

    @Test
    public void testWhenSelectEmptyJWKThenThrowException() throws Exception {
        this.jwkSource = mock(JWKSource.class);
        this.jwtDecrypter = new DefaultJWTDecrypter(this.jwkSource);

        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("1").generate();
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM).keyID("1").build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("abc").claim("foo", "bar").build();
        String jwe = encryptJweWithRSAKey(rsaKey, header, jwtClaimsSet);

        EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwe);

        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtDecrypter.decrypt(encryptedJWT))
                .withMessage("Failed to select a jwk.");
    }

    @Test
    public void testWhenSelectMultipleJWKThenThrowException() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("1").generate();

        this.jwkList.add(rsaKey);
        this.jwkList.add(rsaKey);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM).keyID("1").build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("abc").claim("foo", "bar").build();

        //encrypt
        String jwe = encryptJweWithRSAKey(rsaKey, header, jwtClaimsSet);
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwe);

        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtDecrypter.decrypt(encryptedJWT))
                .withMessage("Found multiple jwk.");
    }

    @Test
    public void testWithMismatchKeyIdThenThrowException() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("1").generate();
        jwkList.add(rsaKey);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM).keyID("1").build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("abc").claim("foo", "bar").build();

        //encrypt
        String jwe = encryptJweWithRSAKey(rsaKey, header, jwtClaimsSet);
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwe);
        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);

        //decrypt jwe
        jwkList.clear();
        jwkList.add(new RSAKeyGenerator(2048).keyID("2").generate());

        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtDecrypter.decrypt(encryptedJWT))
                .withMessage("Failed to select a jwk.");
    }

    @Test
    public void testWithMismatchKeyThenThrowException() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("1").generate();
        jwkList.add(rsaKey);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM).keyID("1").build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("abc").claim("foo", "bar").build();

        //encrypt
        String jwe = encryptJweWithRSAKey(rsaKey, header, jwtClaimsSet);
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwe);
        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);

        //reset keys
        jwkList.clear();
        jwkList.add(new RSAKeyGenerator(2048).keyID("1").generate());

        //decrypt jwe
        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtDecrypter.decrypt(encryptedJWT))
                .withCauseInstanceOf(JOSEException.class)
                .withMessageStartingWith("Failed to encrypt jwt.");
    }

    @Test
    public void testWhenHeadNotKidThenSuccess() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("1").generate();
        jwkList.add(rsaKey);

        //header don't has kid
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM).build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("abc").claim("foo", "bar").build();

        //encrypt
        String jwe = encryptJweWithRSAKey(rsaKey, header, jwtClaimsSet);
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwe);
        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);

        //decrypt jwe
        jwtDecrypter.decrypt(encryptedJWT);
        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.DECRYPTED);
    }

    @Test
    public void testWithRSAKeyThenSuccess() throws Exception {
        RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("1").generate();
        jwkList.add(rsaKey);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM).keyID("1").build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("abc").claim("foo", "bar").build();

        //encrypt
        String jwe = encryptJweWithRSAKey(rsaKey, header, jwtClaimsSet);
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwe);
        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);

        //decrypt jwe
        jwtDecrypter.decrypt(encryptedJWT);

        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.DECRYPTED);
        assertThat(encryptedJWT.getHeader().getKeyID()).isEqualTo(rsaKey.getKeyID());
        assertThat(encryptedJWT.getJWTClaimsSet().getClaim("foo")).isEqualTo(jwtClaimsSet.getClaim("foo"));
    }

    @Test
    public void testWithECKeyThenSuccess() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).keyID("1").generate();
        jwkList.add(ecKey);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128GCM).keyID("1").build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("abc").claim("foo", "bar").build();

        //encrypt
        String jwe = encryptJweWithECKey(ecKey, header, jwtClaimsSet);
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwe);
        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);

        //decrypt jwe
        jwtDecrypter.decrypt(encryptedJWT);

        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.DECRYPTED);
        assertThat(encryptedJWT.getHeader().getKeyID()).isEqualTo(ecKey.getKeyID());
        assertThat(encryptedJWT.getJWTClaimsSet().getClaim("foo")).isEqualTo(jwtClaimsSet.getClaim("foo"));
    }

    @Test
    public void testWithOceteSequenceKeyThenSuccess() throws Exception {
        OctetSequenceKey ecKey = new OctetSequenceKeyGenerator(256).keyID("1").generate();
        jwkList.add(ecKey);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.A256GCMKW, EncryptionMethod.A128GCM).keyID("1").build();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().issuer("abc").claim("foo", "bar").build();

        //encrypt
        String jwe = encryptJweWithOctetSequenceKey(ecKey, header, jwtClaimsSet);
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(jwe);
        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.ENCRYPTED);

        //decrypt jwe
        jwtDecrypter.decrypt(encryptedJWT);

        assertThat(encryptedJWT.getState()).isEqualTo(JWEObject.State.DECRYPTED);
        assertThat(encryptedJWT.getHeader().getKeyID()).isEqualTo(ecKey.getKeyID());
        assertThat(encryptedJWT.getJWTClaimsSet().getClaim("foo")).isEqualTo(jwtClaimsSet.getClaim("foo"));
    }
}
