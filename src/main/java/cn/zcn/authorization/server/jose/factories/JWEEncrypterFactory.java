package cn.zcn.authorization.server.jose.factories;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEProvider;
import com.nimbusds.jose.jwk.JWK;

public interface JWEEncrypterFactory extends JWEProvider {

    JWEEncrypter createJWEEncrypter(JWEHeader header, JWK key) throws JOSEException;
}
