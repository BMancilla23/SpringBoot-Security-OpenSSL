package com.spring.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.spring.security.services.IJWTUtilityService;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {
    
    // Dependencia inyectada para el servicio de utilidades JWT
    private final IJWTUtilityService jwUtilityService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        // Configura la seguridad de Spring Security
        return http
        // Deshabilita la protección CSRF ya que se utiliza JWT
        .csrf(csrf -> csrf.disable())
        // Define las autorizaciones para las solicitudes HTTP
        .authorizeHttpRequests(authRequest -> authRequest
        // Permite todas las solicitudes que comiencen con "/auth/"
        .requestMatchers("/auth/**")
        .permitAll()
        // Cualquier otra solicitud requiere autenticación
        .anyRequest().authenticated())
        // Configura la gestión de sesiones (sin estado)
        .sessionManagement(sessionManager -> 
        sessionManager.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        // Agrega el filtro de autorización JWT antes del filtro de autenticación por nombre de usuario y contraseña
        .addFilterBefore(new JWTAuthorizationFilter(jwUtilityService), UsernamePasswordAuthenticationFilter.class)
        // Configura el manejo de excepciones de autenticación
        .exceptionHandling(exceptionHandling -> 
            exceptionHandling
            // Establece el punto de entrada para la autenticación fallido (código 401 Unouthorized)
            .authenticationEntryPoint((request, response, authException) ->{ response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");})
        ).build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder(){
        // Proporciona un codificador de contraseñas utilizando BCrypt
        return new BCryptPasswordEncoder();
    }
}
