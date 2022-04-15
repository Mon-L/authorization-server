package cn.zcn.authorization.server.jose;

import cn.zcn.authorization.server.exception.JOSERuntimeException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWEDecrypterFactory;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

public class DefaultJWTEncrypterTest {

    private List<JWK> jwkList;

    private JWKSource<SecurityContext> jwkSource;

    private JWTEncrypter jwtEncrypter;

    private JWEDecrypterFactory jweDecrypterFactory;

    @BeforeEach
    public void init() {
        this.jwkList = new ArrayList<>();
        this.jwkSource = (jwkSelector, context) -> jwkSelector.select(new JWKSet(this.jwkList));

        this.jwtEncrypter = new DefaultJWTEncrypter(jwkSource);

        jweDecrypterFactory = new DefaultJWEDecrypterFactory();
    }

    @Test
    public void initWhenNullJWKSourceThenThrowException() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new DefaultJWTEncrypter(null));
    }

    @Test
    public void testWhenSelectEmptyJWKThenThrowException() {
        this.jwkSource = mock(JWKSource.class);
        this.jwtEncrypter = new DefaultJWTEncrypter(this.jwkSource);

        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM)
                .keyID("1")
                .build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();

        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtEncrypter.encrypt(header, claimsSet))
                .withMessageStartingWith("Failed to select a jwk");
    }

    @Test
    public void testWhenSelectMultipleJWKThenThrowException() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("1").generate();
        this.jwkList.add(key);
        this.jwkList.add(key);

        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                .keyID("1")
                .build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();

        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtEncrypter.encrypt(header, claimsSet))
                .withMessageStartingWith("Found multiple jwk.");
    }

    @Test
    public void testWhenNoKeyIDThenMatchAlg() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("1").generate();
        this.jwkList.add(key);

        //jwe header hasn't key id.
        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                .build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("abc")
                .claim("foo", "bar")
                .build();

        //encrypt
        EncryptedJWT jwe = jwtEncrypter.encrypt(header, claimsSet);

        assertThat(jwe.getState()).isEqualTo(JWEObject.State.ENCRYPTED);
        assertThat(jwe.getHeader().getKeyID()).isEqualTo(key.getKeyID());

        //decrypt
        EncryptedJWT decryptedJwe = EncryptedJWT.parse(jwe.serialize());

        assertThat(decryptedJwe.getState()).isEqualTo(JWEObject.State.ENCRYPTED);

        JWEDecrypter decrypter = jweDecrypterFactory.createJWEDecrypter(decryptedJwe.getHeader(), key.toPrivateKey());
        decryptedJwe.decrypt(decrypter);

        assertThat(decryptedJwe.getState()).isEqualTo(JWEObject.State.DECRYPTED);
        assertThat(decryptedJwe.getJWTClaimsSet().getIssuer()).isEqualTo(claimsSet.getIssuer());
        assertThat(decryptedJwe.getJWTClaimsSet().getClaim("foo")).isEqualTo(claimsSet.getClaim("foo"));
    }

    @Test
    public void testWithKeyIDThenSuccess() throws Exception {
        OctetSequenceKey key = new OctetSequenceKeyGenerator(256).keyID("1").generate();
        this.jwkList.add(key);

        //jwe header hasn't key id.
        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                .keyID("1")
                .build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("abc")
                .claim("foo", 1)
                .build();

        //encrypt
        EncryptedJWT jwe = jwtEncrypter.encrypt(header, claimsSet);

        assertThat(jwe.getState()).isEqualTo(JWEObject.State.ENCRYPTED);
        assertThat(jwe.getHeader().getKeyID()).isEqualTo(key.getKeyID());

        //decrypt
        EncryptedJWT decryptedJwe = EncryptedJWT.parse(jwe.serialize());

        assertThat(decryptedJwe.getState()).isEqualTo(JWEObject.State.ENCRYPTED);

        JWEDecrypter decrypter = jweDecrypterFactory.createJWEDecrypter(decryptedJwe.getHeader(), key.toSecretKey());
        decryptedJwe.decrypt(decrypter);

        assertThat(decryptedJwe.getState()).isEqualTo(JWEObject.State.DECRYPTED);
        assertThat(decryptedJwe.getJWTClaimsSet().getIssuer()).isEqualTo(jwe.getJWTClaimsSet().getIssuer());
        assertThat(decryptedJwe.getJWTClaimsSet().getIntegerClaim("foo")).isEqualTo(jwe.getJWTClaimsSet().getIntegerClaim("foo"));
    }

    @Test
    public void testWhenKeyIDAndAlgDontMatchThenThrowException() throws Exception {
        OctetSequenceKey key = new OctetSequenceKeyGenerator(256).keyID("1").generate();
        this.jwkList.add(key);

        //jwe header hasn't key id.
        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID("1")
                .build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();

        assertThatExceptionOfType(JOSERuntimeException.class)
                .isThrownBy(() -> jwtEncrypter.encrypt(header, claimsSet))
                .withMessage("Failed to select a jwk.");
    }

    @Test
    public void testEncryptThenReturnJWEObject() throws Exception {
        OctetSequenceKey key = new OctetSequenceKeyGenerator(256).keyID("1").generate();
        this.jwkList.add(key);

        //jwe header hasn't key id.
        JWEHeader header = new JWEHeader
                .Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                .build();

        Payload payload = new Payload("123");

        //encrypt
        JWEObject jwe = jwtEncrypter.encrypt(header, payload);

        assertThat(jwe.getState()).isEqualTo(JWEObject.State.ENCRYPTED);
        assertThat(jwe.getHeader().getKeyID()).isEqualTo(key.getKeyID());
        assertThat(jwe.getPayload().toString()).isEqualTo(payload.toString());

        //decrypt
        EncryptedJWT decryptedJwe = EncryptedJWT.parse(jwe.serialize());

        assertThat(decryptedJwe.getState()).isEqualTo(JWEObject.State.ENCRYPTED);

        JWEDecrypter decrypter = jweDecrypterFactory.createJWEDecrypter(decryptedJwe.getHeader(), key.toSecretKey());
        decryptedJwe.decrypt(decrypter);

        assertThat(decryptedJwe.getState()).isEqualTo(JWEObject.State.DECRYPTED);
        assertThat(decryptedJwe.getHeader().getKeyID()).isEqualTo(jwe.getHeader().getKeyID());
        assertThat(decryptedJwe.getPayload().toString()).isEqualTo(jwe.getPayload().toString());
    }
}
