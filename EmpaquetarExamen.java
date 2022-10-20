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
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EmpaquetarExamen {
    public final static void main(String[] args) { // <nombre_examen.txt> <nombre_paquete> <profesor.publica> <alumno.privada>
        // Anadir provider (el provider por defecto no soporta RSA)
        Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

        try {

            // Leemos el archivo del examen
            byte[] examen = Files.readAllBytes(Paths.get(args[0]));
            System.out.println("Examen cargado");

            // Crear clave DES
            KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
            generadorDES.init(56); // clave de 56 bits
            SecretKey claveDES = generadorDES.generateKey();
            System.out.println("Clave DES generada");

            // Crear cifrador DES
            Cipher cifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding");
            // Crear cifrador RSA
            Cipher cifradorRSA = Cipher.getInstance("RSA", "BC");
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

            // Inicializar cifrador DES en modo CIFRADO 
            cifradorDES.init(Cipher.ENCRYPT_MODE, claveDES);
            byte[] examenCifrado = cifradorDES.doFinal(examen); // Completar cifrado (procesa relleno, puede devolver texto)
            System.out.println("Examen cifrado obtenido");

            // Recuperar clave publica del profesor
            PublicKey clavePublica = recuperarClavePublicaProfesor(args[2], keyFactoryRSA);
            System.out.println("Clave publica del profesor obtenida");
            // Iniciar cifrado
            cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePublica);
            // Cifrar clave que se utilizó para cifrar el examen
            byte[] claveDES_cifrada = cifradorRSA.doFinal(claveDES.getEncoded());
            System.out.println("Clave DES cifrada");

            // Leer clave alumno privada
            PrivateKey clavePrivada = recuperarClavePrivadaAlumno(args[3], keyFactoryRSA);
            System.out.println("Clave privada del alumno obtenida");
            // Firma digital Alumno con claveDES_cifrada y examenCifrado
            byte[] hashAlumno = realizarFirmaDigital(examenCifrado, claveDES_cifrada, clavePrivada);
            System.out.println("Firma digital realizada");

            crearExamenEmpaquetado(args[1], examenCifrado, claveDES_cifrada, hashAlumno);
            System.out.println("Examen Empaquetado creado");

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException | NoSuchProviderException | InvalidKeySpecException | SignatureException
                | IOException e) {
            e.printStackTrace();
        }
    }

    private static void crearExamenEmpaquetado(String nombre, byte[] examenCifrado, byte[] claveDES_cifrada, byte[] hashAlumno) {
        Paquete p = new Paquete();
        p.anadirBloque("Examen Cifrado", examenCifrado);
        p.anadirBloque("Clave Cifrada", claveDES_cifrada);
        p.anadirBloque("Hash Alumno", hashAlumno);
        p.escribirPaquete(nombre + ".paquete");
    }

    private static byte[] realizarFirmaDigital(byte[] examenCifrado, byte[] claveDES_cifrada, PrivateKey clavePrivada)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature firmaAlumno = Signature.getInstance("MD5withRSA");
        firmaAlumno.initSign(clavePrivada);
        firmaAlumno.update(examenCifrado);
        firmaAlumno.update(claveDES_cifrada);
        byte[] hashAlumno = firmaAlumno.sign();
        return hashAlumno;
    }

    private static PublicKey recuperarClavePublicaProfesor(String clave, KeyFactory keyFactoryRSA)
            throws IOException, InvalidKeySpecException {
        byte[] bufferPub = Files.readAllBytes(Paths.get(clave));
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
        PublicKey clavePublica = keyFactoryRSA.generatePublic(clavePublicaSpec);
        return clavePublica;
    }

    private static PrivateKey recuperarClavePrivadaAlumno(String clave, KeyFactory keyFactoryRSA)
            throws IOException, InvalidKeySpecException {
        byte[] bufferPriv = Files.readAllBytes(Paths.get(clave));
        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
        PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
        return clavePrivada;
    }
}
