import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarExamen {

    public final static void main(String[] args) { // <nombre_paquete.paquete> <nombre_examen_claro.txt> <profesor.privada> <alumno.publica> <autoridad.publica>        
        // Anadir provider (el provider por defecto no soporta RSA)
        Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

        try {
            Cipher cifradorRSA = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

            // Cargar examen.paquete
            Paquete p = new Paquete(args[0]);
            byte[] examenCifrado = p.getContenidoBloque("Examen Cifrado"); // Leer examen cifrado
            byte[] claveDES_cifrada = p.getContenidoBloque("Clave Cifrada"); // Leer clave cifrada
            byte[] firmaCifrada = p.getContenidoBloque("Hash Alumno"); // Leer hash alumno
            byte[] fechaHora = p.getContenidoBloque("Fecha Hora"); // Leer fecha
            byte[] sellado = p.getContenidoBloque("Sellado Tiempo"); // Leer sellado
            System.out.println("Bloques necesarios del paquete cargados");

            // Comprobar FIRMAs DIGITALES
            // Recuperar clave publica de la autoridad de sellado
            PublicKey claveSellado = recuperarClavePublicaAutoridad(args[4], keyFactoryRSA);
            System.out.println("Clave publica de la autoridad obtenida");

            // Verificar sellado de la autoridad de sellado
            if (esSelladoValido(examenCifrado, claveDES_cifrada, firmaCifrada, claveSellado, fechaHora, sellado)) {
                // Recuperar clave publica del alumno
                System.out.print("Fecha de sellado: ");
                mostrarBytes(fechaHora);
                System.out.println();

                PublicKey clavePublica = recuperarClavePublicaAlumno(args[3], keyFactoryRSA);
                System.out.println("Clave publica del alumno obtenida");

                // Verificar firma digital del alumno
                if (esFirmaAlumnoValida(examenCifrado, claveDES_cifrada, clavePublica, firmaCifrada)) {
                    // Recuperar clave privada del profesor
                    PrivateKey clavePrivada = recuperarClavePrivadaProfesor(args[2], keyFactoryRSA);
                    System.out.println("Clave privada del profesor obtenida");

                    cifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivada); // Descrifra con la clave privada
                    // Obtener clave descifrada
                    byte[] bytesClaveDES = cifradorRSA.doFinal(claveDES_cifrada);
                    System.out.println("Clave DES descifrada obtenida");

                    // Crear cifradorDES
                    Cipher cifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding");
                    SecretKey claveDES = new SecretKeySpec(bytesClaveDES, "DES");
                    cifradorDES.init(Cipher.DECRYPT_MODE, claveDES);

                    byte[] examen_claro = cifradorDES.doFinal(examenCifrado);

                    // Obtener Examen limpio
                    crearExamenLimpio(args[1], examen_claro);

                    System.out.println("Examen en limpio obtenido");

                } else {
                    System.err.println("ERROR: FIRMA ALUMNO NO VALIDA");
                }
            } else {
                System.err.println("ERROR: SELLADO NO VALID0");
            }

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException
                | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException | IOException
                | SignatureException e) {
            e.printStackTrace();
        }
    }

    private static void crearExamenLimpio(String nombreExamen, byte[] examen_claro) {
        File file = new File(nombreExamen);
        try {
            FileOutputStream out = new FileOutputStream(file);
            out.write(examen_claro);
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static boolean esSelladoValido(byte[] examenCifrado, byte[] claveDES_cifrada, byte[] firmaCifrada,
            PublicKey claveSellado, byte[] fechaHora, byte[] sellado)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature selladoTiempo = Signature.getInstance("MD5withRSA");
        selladoTiempo.initVerify(claveSellado);
        selladoTiempo.update(fechaHora);
        selladoTiempo.update(examenCifrado);
        selladoTiempo.update(claveDES_cifrada);
        selladoTiempo.update(firmaCifrada);
        if (selladoTiempo.verify(sellado)) {
            System.out.println("Sellado correcto!!");
            return true;
        } else {
            System.out.println("Error en el sellado.");
            return false;
        }
    }

    private static boolean esFirmaAlumnoValida(byte[] examenCifrado, byte[] claveDES_cifrada, PublicKey clavePublica,
            byte[] firmaCifrada) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature firmaAlumno = Signature.getInstance("MD5withRSA");
        firmaAlumno.initVerify(clavePublica);
        firmaAlumno.update(examenCifrado);
        firmaAlumno.update(claveDES_cifrada);
        if (firmaAlumno.verify(firmaCifrada)) {
            System.out.println("Firma digital correcta!!");
            return true;
        } else {
            System.out.println("Error en la firma digital.");
            return false;
        }
    }

    private static PublicKey recuperarClavePublicaAutoridad(String clave, KeyFactory keyFactoryRSA)
            throws IOException, InvalidKeySpecException {
        byte[] bufferSellado = Files.readAllBytes(Paths.get(clave));
        X509EncodedKeySpec claveSelladoSpec = new X509EncodedKeySpec(bufferSellado);
        PublicKey claveSellado = keyFactoryRSA.generatePublic(claveSelladoSpec);
        return claveSellado;
    }

    private static PublicKey recuperarClavePublicaAlumno(String clave, KeyFactory keyFactoryRSA)
            throws IOException, InvalidKeySpecException {
        byte[] bufferPub = Files.readAllBytes(Paths.get(clave));
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
        PublicKey clavePublica = keyFactoryRSA.generatePublic(clavePublicaSpec);
        return clavePublica;
    }

    private static PrivateKey recuperarClavePrivadaProfesor(String clave, KeyFactory keyFactoryRSA)
            throws IOException, InvalidKeySpecException {
        byte[] bufferPriv = Files.readAllBytes(Paths.get(clave));
        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
        PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
        return clavePrivada;
    }

    public static void mostrarBytes(byte[] buffer) {
        System.out.write(buffer, 0, buffer.length);
    }
}
