package com.spring.security.services;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

public interface IJWTUtilityService {

    /**
     * Genera un token JWT basado en el ID de usuario proporcionado.
     *
     * @param idUsuario El ID del usuario para el que se genera el token.
     * @return El token JWT generado como una cadena.
     * @throws InvalidKeySpecException Si hay un problema con la especificación de la clave.
     * @throws NoSuchAlgorithmException Si no se admite el algoritmo especificado.
     * @throws IOException Si hay un error durante las operaciones de E/S.
     * @throws JOSEException Si hay una excepción general relacionada con JOSE.
     */
    public String generateJWT(Long userId) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, JOSEException;

    /**
     * Analiza un token JWT y recupera el conjunto de reclamaciones de él.
     *
     * @param jwt La cadena del token JWT a analizar.
     * @return El objeto JWTClaimsSet analizado que contiene información del token.
     * @throws NoSuchAlgorithmException Si no se admite el algoritmo especificado.
     * @throws InvalidKeySpecException Si hay un problema con la especificación de la clave.
     * @throws IOException Si hay un error durante las operaciones de E/S.
     * @throws ParseException Si el análisis del token falla debido a un formato no válido.
     * @throws JOSEException Si hay una excepción general relacionada con JOSE.
     */
    public JWTClaimsSet parseJWT(String jwt) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, ParseException, JOSEException;
}
