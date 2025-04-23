package com.example.starter.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({
        SecurityConfig.class,
        JwtAuthenticationEntryPoint.class,
        JwtAuthenticationFilter.class,
        JwtValidator.class
})
public class SecurityAutoConfiguration {
}
