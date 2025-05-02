package com.github.ayush30197.spring_security_demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());

        return  provider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       /*
        //Non Lambda code -- Imperative Style
        Customizer<CsrfConfigurer<HttpSecurity>> csrfConfigurerCustomizer = new Customizer<CsrfConfigurer<HttpSecurity>>() {
            @Override
            public void customize(CsrfConfigurer<HttpSecurity> httpSecurityCsrfConfigurer) {
                httpSecurityCsrfConfigurer.disable();
            }
        };

        http.csrf(csrfConfigurerCustomizer);

        Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry> authorizationManagerRequestMatcherRegistryCustomizer = new Customizer<AuthorizeHttpRequestsConfigurer<org.springframework.security.config.annotation.web.builders.HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>() {
            @Override
            public void customize(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorizationManagerRequestMatcherRegistry) {
                authorizationManagerRequestMatcherRegistry.anyRequest().authenticated();
            }
        };
        http.authorizeHttpRequests(authorizationManagerRequestMatcherRegistryCustomizer);
        */

        //Lambda way of customizing security config
       return http
                .csrf(csrf -> csrf.disable())  //Disables the csrf
                .authorizeHttpRequests(req -> req.anyRequest().authenticated()) //Authorize any http request
                //.formLogin(Customizer.withDefaults()) //Provides form login feature
                .httpBasic(Customizer.withDefaults()) //Uses basic auth
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //Making application stateless
                .build();
    }

    /*
    //Setting up users via InMemoryUserManager
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User
                            .withDefaultPasswordEncoder()
                            .username("bansal")
                            .password("1234")
                            .roles("USER")
                            .build();

        UserDetails admin = User
                .withDefaultPasswordEncoder()
                .username("admin")
                .password("admin@123")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

     */
}
