package com.smallproject.gmf.springcloudgatewayservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.cloud.netflix.zuul.EnableZuulServer;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableZuulProxy
public class SpringCloudGatewayServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringCloudGatewayServiceApplication.class, args);
	}

    @Bean
    public SimpleFilter simpleFilter() {
        return new SimpleFilter();
    }

}
