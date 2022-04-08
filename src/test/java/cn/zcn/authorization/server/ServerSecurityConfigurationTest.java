package cn.zcn.authorization.server;

import cn.zcn.authorization.server.configuration.EnableAuthorizationServer;
import cn.zcn.authorization.server.configuration.ServerSecurityConfigurationAdapter;
import cn.zcn.authorization.server.configurer.AuthorizationEndpointConfigurer;
import cn.zcn.authorization.server.configurer.ClientAuthenticationConfigurer;
import cn.zcn.authorization.server.configurer.ServerSecurityConfigurer;
import cn.zcn.authorization.server.configurer.TokenEndpointConfigurer;
import org.springframework.security.config.Customizer;

public class ServerSecurityConfigurationTest {

    @EnableAuthorizationServer
    private class MyConfigurationTest extends ServerSecurityConfigurationAdapter {
        @Override
        public void configure(ServerSecurityConfigurer serverSecurityConfigurer) {

            serverSecurityConfigurer
                    .clientAuthentication(new Customizer<ClientAuthenticationConfigurer>() {
                        @Override
                        public void customize(ClientAuthenticationConfigurer configurer) {
                            
                        }
                    })
                    .authorizationEndpoint(new Customizer<AuthorizationEndpointConfigurer>() {
                        @Override
                        public void customize(AuthorizationEndpointConfigurer configurer) {

                        }
                    })
                    .tokenEndpoint(new Customizer<TokenEndpointConfigurer>() {
                        @Override
                        public void customize(TokenEndpointConfigurer tokenEndpointConfigurer) {

                        }
                    });
        }
    }
}
