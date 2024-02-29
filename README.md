# SpringBoot - Security - OpenSSL

## Creación de clave privada y pública

1. crearse una carpeta de jwtKeys en resources

2. dirigirse a la ruta /c/Users/Adev/Desktop/Spring/security/src/main/resources/jwtkeys

3. generar clave privada con openssl

```cmd
openssl genrsa -out private_key.pem 2048
```

4. generar clave pública con openssl

```cmd
openssl rsa -pubout -in private_key.pem -out public_key.pem
```
