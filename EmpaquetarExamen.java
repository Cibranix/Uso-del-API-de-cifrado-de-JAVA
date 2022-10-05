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
    public final static void main(String[] args) {
		// Anadir provider  (el provider por defecto no soporta RSA)
		Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

        try {
            //Leemos el archivo del examen
            byte[] examen = Files.readAllBytes(Paths.get(args[0]));

            //Crear e inicializar clave DES
            System.out.println("Generar clave DES");
            KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
            generadorDES.init(56); // clave de 56 bits
            SecretKey claveDES = generadorDES.generateKey();

            //Crear cifrador DES
            Cipher cifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding");

            //Inicializar cifrador en modo CIFRADO DES
            System.out.println("Inicializar cifrador DES");
            cifradorDES.init(Cipher.ENCRYPT_MODE, claveDES);
            byte[] examenCifrado = cifradorDES.doFinal(examen); // Completar cifrado (procesa relleno, puede devolver texto)

            Paquete p = new Paquete();
            p.anadirBloque("Examen Cifrado", examenCifrado);
            
            //Crear cifrador RSA
            Cipher cifradorRSA = Cipher.getInstance("RSA", "BC");
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

            //Recuperar clave
            byte[] bufferPub = Files.readAllBytes(Paths.get(args[2]));
            X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
            PublicKey clavePublica = keyFactoryRSA.generatePublic(clavePublicaSpec);
            
            //Iniciar cifrado
            cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePublica);

            System.out.println("Cifrar con clave publica del profesor");
            byte[] claveDES_cifrada = cifradorRSA.doFinal(claveDES.getEncoded());
            System.out.println("CLAVE CIFRADA");

            p.anadirBloque("Clave Cifrada", claveDES_cifrada);

            //Empezar con la firma digital
            Signature firmaAlumno = Signature.getInstance("MD5withRSA");

            //Leer clave alumno privada
            byte[] bufferPriv = Files.readAllBytes(Paths.get(args[3]));
            PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
            PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

            //Firma digital Alumno con claveDES_cifrada y examenCifrado
            System.out.println("Realizar firma digital");
            firmaAlumno.initSign(clavePrivada);
            firmaAlumno.update(examenCifrado);
            firmaAlumno.update(claveDES_cifrada);

            byte [] hashAlumno = firmaAlumno.sign();

            p.anadirBloque("Hash Alumno", hashAlumno);
            
            p.escribirPaquete(args[1]+".paquete");
         } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException | NoSuchProviderException | InvalidKeySpecException | SignatureException
                | IOException e) {
            e.printStackTrace();
        }
    }
}
