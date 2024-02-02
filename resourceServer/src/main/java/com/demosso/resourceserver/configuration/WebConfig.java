package com.demosso.resourceserver.configuration;

import com.demosso.resourceserver.filter.AddResponseHeaderFilter;
import jakarta.servlet.Filter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WebConfig {

    @Bean
    public Filter addResponseHeaderFilter() {
        return new AddResponseHeaderFilter();
    }
}
