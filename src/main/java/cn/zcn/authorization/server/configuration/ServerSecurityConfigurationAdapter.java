package cn.zcn.authorization.server.configuration;


import cn.zcn.authorization.server.configurer.ServerSecurityConfigurer;

public abstract class ServerSecurityConfigurationAdapter {

    public abstract void configure(ServerSecurityConfigurer configurer);

}
