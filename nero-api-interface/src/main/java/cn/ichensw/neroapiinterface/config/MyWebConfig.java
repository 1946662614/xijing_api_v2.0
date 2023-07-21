package cn.ichensw.neroapiinterface.config;

import cn.ichensw.neroapiinterface.interceptor.DyeDataInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 网络配置
 * 这段代码是一个配置类，用于注册一个拦截器。该类实现了WebMvcConfigurer接口，并重写了其中的addInterceptors方法。
 * 在addInterceptors方法中，通过调用InterceptorRegistry对象的addInterceptor方法，
 * 注册了一个名为DyeDataInterceptor的拦截器，并使用addPathPatterns方法指定了拦截的路径模式为"/**"，即所有的请求都会被该拦截器所拦截。
 * 拦截器的作用是在请求进入Controller方法之前或之后进行拦截和处理，可以用于实现一些通用的功能，例如权限验证、日志记录、参数校验等。
 * 在这段代码中，通过注册DyeDataInterceptor拦截器，并将其应用到所有的请求上，可以实现对请求的流量染色处理。
 * 具体的流量染色逻辑可以在DyeDataInterceptor中实现，根据实际需求对请求进行染色操作，例如添加染色标识的请求头、修改请求参数等。
 * 需要注意的是，该配置类需要被Spring容器扫描到，可以通过@ComponentScan或者@Configuration注解将其纳入Spring容器管理。
 * @author 嘻精
 * @date 2023/07/21
 */
@Configuration
public class MyWebConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new DyeDataInterceptor())
                .addPathPatterns("/**");
    }
}
