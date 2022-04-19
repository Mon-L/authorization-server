# authorization-server

基于 Spring Security 的支持细粒度配置的 OAuth2/OpenID Connect 认证授权服务框架。

**优点：**

* 更简单、更易理解的接口
* 分功能的细粒度配置方式
* 支持多种客户端认证模式，如client secret、client assertion
* 支持 JWT/JWK/JWS/JWE，用于加验签、加解密
* 支持使用 Access Token 访问受保护的资源
* .....(未完待续)

**缺失功能：**

* 令牌自省
* 令牌吊销
* PKCE
* ID Token
* 支持完整的 Open ID Connect 协议。

# 使用方式

``` java
//添加 @EnableAuthorizationServer 注解，并继承 AuthorizationServerConfigurationAdapter 配置类
@EnableAuthorizationServer 
private class OAuth2Configuration extends AuthorizationServerConfigurationAdapter {

    @Override
    public void configure(AuthorizationServerConfigurer authorizationServerConfigurer) {
      	//自定义授权服务功能
        authorizationServerConfigurer
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

### AuthorizationServerConfigurer

* clientService

  配置客户端查询类。用于查找客户端，**必须配置**。

* serverConfig

  全局服务配置。可自定义授权端点 Path、令牌端点 Path 等。

* jwkSource

  配置认证授权服务解密、签名密钥集合。

* jwtSigner

  自定义认证授权服务签名功能。缺省实现为 **DefaultJWTSigner**

* jwtDecrypter

  自定义认证授权解密功能。缺省实现为 **DefaultJWTDecrypter**

* clientJOSEService

  自定义验证客户端签名以及加密响应信息的功能。缺省实现为 **DefaultClientJOSEService**

* exceptionWriter

  自定义异常处理类，当授权异常时会使用此接口将异常响应给客户端。异常响应格式必须符合 OAuth2 规范。

  缺省实现为 **DefaultExceptionWriter**。

* requestResolver

  自定义请求解析器，用于解析授权请求、令牌颁发请求。

  缺省实现为 **DefaultRequestResolver**。

* tokenGranter

  自定义令牌颁发流程，用于处理 OAuth2 令牌颁发的流程。

  缺省支持授权码模式、简化模式、密码模式、客户端模式、刷新令牌模式。

* tokneSevice

  设置令牌颁发服务，用于生成、存储、查找访问令牌、刷新令牌，**开发者需要实现对应接口**。

* useAuthenticationManager

  设置用户认证管理器，如果需要使用密码模式，则必须设置该类。

```java
authorizationServerConfigurer
        .clientService(...) //必需
        .serverConfig(...)
        .exceptionWriter(...)
        .jwkSource(...)
        .jwtDecrypter(...)
        .jwtSigner(...)
        .clientJOSESigner(...)
        .useAuthenticationManager(...)
        .tokneSevice(...) //必需
        .requestResolver(...)
        .tokenGranter(...);
```

### ClientAuthenticationConfigurer

用于配置客户端认证功能。

* allowedClientAuthMethods

  配置服务支持的客户端认证方式。缺省支持以下方式 client_secret_basic、client_secret_post、client_secret_jwt、private_key_jwt、none。

* authenticationFailureHandler

  自定义客户端认证失败处理器。非必需，框架自带缺省实现。

* authenticationSuccessHandler

  自定义客户端认证成功处理处理器。非必需，框架自带缺省实现。

```java
authorizationServerConfigurer.clientAuthentication(new Customizer<ClientAuthenticationConfigurer>(){
@Override
public void customize(ClientAuthenticationConfigurer configurer){
        configurer
            .allowedClientAuthMethods(...)
            .authenticationFailureHandler(...)
            .authenticationSuccessHandler(...);
    }
})
```

### TokenAuthenticationConfigurer

用于配置使用 Access Token 作为凭证访问受保护资源的功能

* requestMatcher。缺省拦截 OAuth2 相关端点

  用于匹配需要验证访问令牌的请求

* authenticationManager

  用于验证访问令牌是否有效。缺省实现为 **OAuth2AuthenticationManager**

* authenticationEntryPoint

  用于当访问令牌验证失败时将信息响应给客户端。缺省实现为 **OAuth2AuthenticationEntryPoint**

```java
authorizationServerConfigurer.tokenAuthentication(new Customizer<TokenAuthenticationConfigurer>(){
@Override
public void customize(TokenAuthenticationConfigurer configurer){
        configurer
            .requestMatcher(...)
            .authenticationManager(...)
            .authenticationEntryPoint(...);
    }
})
```

### AuthorizationEndpointConfigurer

配置授权码端点的功能。

* approvalService

  用于管理用户同意。如果需要使用授权码模式，需要实现对应接口。

* authorizationCodeService

  用于授权码颁发、消费功能。如果需要使用授权码模式，需要实现对应接口。

```java
authorizationServerConfigurer.authorizationEndpoint(new Customizer<AuthorizationEndpointConfigurer>(){
@Override
public void customize(AuthorizationEndpointConfigurer configurer){
        configurer
            .approvalService(...)
            .authorizationCodeService(...);
    }
});
```

### TokenEndpointConfigurer

配置令牌端点的功能。

```java
authorizationServerConfigurer.tokenEndpoint(new Customizer<TokenEndpointConfigurer>(){
@Override
public void customize(TokenEndpointConfigurer configurer){

	}
});
```

