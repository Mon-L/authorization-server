# authorization-server
authorization server for java

# 使用方式
``` java
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
```
