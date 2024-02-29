package com.spring.security.services.impl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.spring.security.services.IJWTUtilityService;


@Service
public class JWTUtilityServiceImpl implements IJWTUtilityService{

    // Ruta de la clave privada en el classpath
    @Value("classpath:jwtKeys/private_key.pem")
    private Resource privateKeyResource;

    // Ruta de la clave pública en el classpath
    @Value("classpath:jwtKeys/public_Key.pem")
    private Resource publicKeyResource;

    @Override
    public String generateJWT(Long userId) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, JOSEException{

        // Carga la clave privada
        PrivateKey privateKey = loadPrivateKey(privateKeyResource);

        // Crea un firmador usando la clave privada
        JWSSigner signer = new RSASSASigner(privateKey);

        // Obtiene la fecha actual
        Date now = new Date();

        // Crae el conjunto de claims (reclamaciones) del token
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(userId.toString()) // ID del usuario
                .issueTime(now) // Fecha de emisión
                .expirationTime(new Date(now.getTime() + 14400000)) // Fecha de expiración
                .build();
        
        // Crea un JWT firmado
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        signedJWT.sign(signer);

        // Devuelve el token serializado
        return signedJWT.serialize();
    }

    @Override
    public JWTClaimsSet parseJWT(String jwt) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, ParseException, JOSEException{

        // Carga la clave pública
        PublicKey publicKey = loadPublicKey(publicKeyResource);

        // Crea yn verificador usando la clave pública
        SignedJWT signedJWT = SignedJWT.parse(jwt);

        // Verifica la firma del token
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        if (!signedJWT.verify(verifier)) {
            throw new JOSEException("Invalid signature");
        }

        // Obtiene el conjunto de claims del token
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        // Verifica si el token a expirado
        if (claimsSet.getExpirationTime().before(new Date())) {
            throw new JOSEException("Expired token");
        }

        // Devuelve el conjunto de claims
        return claimsSet;
    }
    
    private PrivateKey loadPrivateKey (Resource resource) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException{
        // Lee la clave privada del archivo PEM
        byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));

        // Elimina encabezados y espacios del texto PEM
        String privateKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replaceAll("\\s", "");

        // Decoidifica la clave en formato Base64
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }

    private PublicKey loadPublicKey(Resource resource) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{

        // Lee los bytes de la clave pública desde el archivo PEM
        byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));

        // Elimina encabezados, pie de página y espacios en blanco del texto PEM
        String publicKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s", "");

        // Decodifica la clave en formato Base64
        byte[] decodedKey = Base64.getDecoder().decode(publicKeyPEM);

        // Crea una instancia de KeyFactory para el algoritmo RSA
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Genera la clave pública utilizando el X509EncodedKeySpec
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));

    }
}
