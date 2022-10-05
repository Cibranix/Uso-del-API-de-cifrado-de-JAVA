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
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SellarExamen {
    public final static void main(String[] args) { // examen.paquete alumno.publica autoridad.privada

        // Anadir provider  (el provider por defecto no soporta RSA)
		Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

        try {
            // Recuperar clave publica del alumno
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
            byte[] bufferPub = Files.readAllBytes(Paths.get(args[1]));
            X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
            PublicKey clavePublica = keyFactoryRSA.generatePublic(clavePublicaSpec);

            //Cargar datos del paquete necesarios
            Paquete p = new Paquete(args[0]);
            byte[] firmaCifrada = p.getContenidoBloque("Hash Alumno");
            byte[] examenCifrado = p.getContenidoBloque("Examen Cifrado");
            byte[] claveDES_cifrada = p.getContenidoBloque("Clave Cifrada");

            //Comprobar FIRMA DIGITAL del alumno
            Signature firmaAlumno = Signature.getInstance("MD5withRSA");
            firmaAlumno.initVerify(clavePublica);
            firmaAlumno.update(examenCifrado);
            firmaAlumno.update(claveDES_cifrada);
            if (firmaAlumno.verify(firmaCifrada)) {
                System.out.println("Firma digital correcta!!");
            } else {
                System.out.println("Error en la firma digital.");
            }

            //Recuperar clave privada de la autoridad
            byte[] bufferPriv = Files.readAllBytes(Paths.get(args[2]));
            PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
            PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

            //Firma de la autoridad de sellado
            Signature selladoTiempo = Signature.getInstance("MD5withRSA");
            selladoTiempo.initSign(clavePrivada);
            Date fechaHora = new Date();
            System.out.println("Fecha y hora actuales: " + fechaHora);
            p.anadirBloque("Fecha Hora", fechaHora.toString().getBytes());
            System.out.println("Añadimos fecha de la firma al paquete");
            selladoTiempo.update(fechaHora.toString().getBytes());
            selladoTiempo.update(examenCifrado);
            selladoTiempo.update(claveDES_cifrada);
            selladoTiempo.update(firmaCifrada);
            byte [] hashSellado = selladoTiempo.sign();
            System.out.println("Sellado de tiempo realizado");

            p.anadirBloque("Sellado Tiempo", hashSellado);
            System.out.println("Sello añadido al paquete");
            
            p.escribirPaquete(args[0]);
            System.out.println("Paquete sobreescrito con los 2 bloques del sellado");

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException
                | SignatureException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
