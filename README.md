# authorization-server

遵循 OAuth2 协议的 Java 授权服务框架

# 使用方式
``` java
//必须添加 @EnableAuthorizationServer 注解，并继承 ServerSecurityConfigurationAdapter 配置类
@EnableAuthorizationServer 
private class OAuth2Configuration extends ServerSecurityConfigurationAdapter {

    @Override
    public void configure(ServerSecurityConfigurer serverSecurityConfigurer) {
      	//自定义授权服务功能
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

# 自定义配置

#### ServerSecurityConfigurer

* clientService

  配置客户端查询类。用于授权服务根据 client id 查找客户端。**该接口必须配置**

* serverConfig

  自定义授权服务配置。可配置授权端点 Path、令牌端点 Path 等。

* exceptionWriter

  自定义异常处理类，当授权异常时会使用此接口将异常响应给客户端。异常响应格式必须符合 OAuth2 规范。默认实现为 **OAuthExceptionWriter**

```java
serverSecurityConfigurer
  	.clientService(...)
  	.serverConfig(...)
  	.exceptionWriter(...)
```

####JOSEConfigurer

用于配置加解密、加验签功能

* jwkSource

  配置解密、签名密钥集合。如不配置密钥，则无法使用 id token 加签、request object 解密等功能。

* jwtSigner

  自定义签名实现类。默认实现为 **DefaultJWTSigner**

* jwtDecrypter

  自定义解密实现类。默认实现为 **DefaultJWTDecrypter**

```java
serverSecurityConfigurer.jose(new Customizer<JOSEConfigurer>() {
  @Override
  public void customize(JOSEConfigurer configurer) {
		configurer.jwkSource(...);
		configurer.jwtDecrypter(...);
		configurer.jwtSigner(...);
  }
})
```

####ClientAuthenticationConfigurer

用于自定义客户端授权功能。

* allowedClientAuthMethods

  配置服务支持的客户端认证方式。默认支持以下方式client_secret_basic、client_secret_post、client_secret_jwt、private_key_jwt、none。

* authenticationFailureHandler

  自定义客户端认证失败处理器。

* authenticationSuccessHandler

  自定义客户端认证成功处理处理器。

```java
serverSecurityConfigurer.clientAuthentication(new Customizer<ClientAuthenticationConfigurer>() {
    @Override
    public void customize(ClientAuthenticationConfigurer configurer) {
      configurer.allowedClientAuthMethods(...);
      configurer.authenticationFailureHandler(...);
      configurer.authenticationSuccessHandler(...);
    }
})
```

####AuthorizationEndpointConfigurer

自定义配置授权码端点功能。

```java
serverSecurityConfigurer.authorizationEndpoint(new Customizer<AuthorizationEndpointConfigurer>() {
  @Override
  public void customize(AuthorizationEndpointConfigurer configurer) {

  }
});
```

####TokenEndpointConfigurer

自定义令牌端点功能。

```java
serverSecurityConfigurer.authorizationEndpoint(new Customizer<TokenEndpointConfigurer>() {
  @Override
  public void customize(TokenEndpointConfigurer configurer) {

  }
});
```

