package cn.zcn.authorization.server.jose.factories;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.jwk.*;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class DefaultJWEEncrypterFactory implements JWEEncrypterFactory {

    public static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS;

    public static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS;

    static {
        Set<JWEAlgorithm> algs = new LinkedHashSet<>();
        algs.addAll(RSAEncrypter.SUPPORTED_ALGORITHMS);
        algs.addAll(ECDHEncrypter.SUPPORTED_ALGORITHMS);
        algs.addAll(DirectEncrypter.SUPPORTED_ALGORITHMS);
        algs.addAll(AESEncrypter.SUPPORTED_ALGORITHMS);
        algs.addAll(PasswordBasedEncrypter.SUPPORTED_ALGORITHMS);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);

        Set<EncryptionMethod> encs = new LinkedHashSet<>();
        encs.addAll(RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS);
        encs.addAll(ECDHEncrypter.SUPPORTED_ENCRYPTION_METHODS);
        encs.addAll(DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS);
        encs.addAll(AESEncrypter.SUPPORTED_ENCRYPTION_METHODS);
        encs.addAll(PasswordBasedEncrypter.SUPPORTED_ENCRYPTION_METHODS);
        SUPPORTED_ENCRYPTION_METHODS = Collections.unmodifiableSet(encs);
    }

    private final JWEJCAContext jcaContext = new JWEJCAContext();

    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {
        return SUPPORTED_ALGORITHMS;
    }

    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {
        return SUPPORTED_ENCRYPTION_METHODS;
    }

    @Override
    public JWEJCAContext getJCAContext() {
        return jcaContext;
    }

    @Override
    public JWEEncrypter createJWEEncrypter(JWEHeader header, JWK key) throws JOSEException {
        JWEEncrypter encrypter;

        if (RSAEncrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
                RSAEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

            if (!(key instanceof RSAKey)) {
                throw JWKException.expectedClass(RSAKey.class);
            }

            encrypter = new RSAEncrypter((RSAKey) key);

        } else if (ECDHEncrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
                ECDHEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

            if (!(key instanceof ECKey)) {
                throw JWKException.expectedClass(ECKey.class);
            }

            encrypter = new ECDHEncrypter((ECKey) key);

        } else if (DirectEncrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
                DirectEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

            if (!(key instanceof OctetSequenceKey)) {
                throw JWKException.expectedClass(OctetSequenceKey.class);
            }

            DirectEncrypter directDecrypter = new DirectEncrypter((OctetSequenceKey) key);

            if (!directDecrypter.supportedEncryptionMethods().contains(header.getEncryptionMethod())) {
                throw new KeyLengthException(header.getEncryptionMethod().cekBitLength(), header.getEncryptionMethod());
            }

            encrypter = directDecrypter;

        } else if (AESEncrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
                AESEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

            if (!(key instanceof OctetSequenceKey)) {
                throw JWKException.expectedClass(OctetSequenceKey.class);
            }

            AESEncrypter aesDecrypter = new AESEncrypter((OctetSequenceKey) key);

            if (!aesDecrypter.supportedJWEAlgorithms().contains(header.getAlgorithm())) {
                throw new KeyLengthException(header.getAlgorithm());
            }

            encrypter = aesDecrypter;

        } else if (PasswordBasedEncrypter.SUPPORTED_ALGORITHMS.contains(header.getAlgorithm()) &&
                PasswordBasedEncrypter.SUPPORTED_ENCRYPTION_METHODS.contains(header.getEncryptionMethod())) {

            if (!(key instanceof OctetSequenceKey)) {
                throw JWKException.expectedClass(OctetSequenceKey.class);
            }

            byte[] password = ((OctetSequenceKey) key).toByteArray();
            encrypter = new PasswordBasedEncrypter(password, 11, 1100);

        } else {
            throw new JOSEException("Unsupported JWE algorithm or encryption method");
        }

        // Apply JCA context
        encrypter.getJCAContext().setSecureRandom(jcaContext.getSecureRandom());
        encrypter.getJCAContext().setProvider(jcaContext.getProvider());
        encrypter.getJCAContext().setKeyEncryptionProvider(jcaContext.getKeyEncryptionProvider());
        encrypter.getJCAContext().setMACProvider(jcaContext.getMACProvider());
        encrypter.getJCAContext().setContentEncryptionProvider(jcaContext.getContentEncryptionProvider());

        return encrypter;
    }
}
