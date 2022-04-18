package cn.zcn.authorization.server.configuration;


import cn.zcn.authorization.server.configurer.AuthorizationServerConfigurer;

public abstract class AuthorizationServerConfigurationAdapter {

    public abstract void configure(AuthorizationServerConfigurer configurer);

}
