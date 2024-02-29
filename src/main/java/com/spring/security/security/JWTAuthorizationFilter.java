package com.spring.security.security;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nimbusds.jwt.JWTClaimsSet;
import com.spring.security.services.IJWTUtilityService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JWTAuthorizationFilter extends OncePerRequestFilter{

    // Dependencia inyectada para el servicio de utilidades JWT
    private final IJWTUtilityService jwtUtilityService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Obtiene la cabecera de autorización de la petición
        String header = request.getHeader("Authorization");

        // Si la cabecera no exixste o no empieza con "Bearer "
        if (header == null || !header.startsWith("Bearer ")) {
            // Continua con la siguiente cadena de filtros
            filterChain.doFilter(request, response);
            return;
        }

        // Extrae el token de la cabecera, aaliminando "Bearer "
        String token = header.substring(7);

        try {
            // Parsea el token utilizando el servicio de utilidades JWT
            JWTClaimsSet claims = jwtUtilityService.parseJWT(token);

            // Crea un token de autenticación de Spring Security
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                // Sujeto del token (identificador del usuario)
                claims.getSubject(),
                // La contraseña vacía de autoridades ya que no se cargan en este filtro
                null,
                // Colección vacía de autoridades ya que no se cargan en este filtro
                Collections.emptyList());

                // Establece el token de autenticación en el contexto de seguridad de Spring 
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        } catch (Exception e) {
            // Manejar la excepción de forma adecuada 
            System.out.println("Error al procesar el token: " + e.getMessage());
        }

        // Continua con la siguente cadena de filtros
        filterChain.doFilter(request, response);
    }
    
}
