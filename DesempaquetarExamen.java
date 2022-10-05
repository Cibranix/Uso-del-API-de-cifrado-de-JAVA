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

    public final static void main(String[] args) { //paquete examen_claro profesor.privada alumno.publica autoridad.publica
        // Anadir provider  (el provider por defecto no soporta RSA)
	    Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

        //Obtener CLAVE CIFRADA (profesor.privada) RSA
        byte[] examen_claro;
        try {
            Cipher cifradorRSA = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
            
            byte[] bufferPriv = Files.readAllBytes(Paths.get(args[2]));
            PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
            PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
            System.out.println("Clave privada del profesor recuperada");

            cifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivada); // Descrifra con la clave privada
            
            //Leer clave cifrada
            Paquete p = new Paquete(args[0]);
            byte [] claveDES_cifrada = p.getContenidoBloque("Clave Cifrada");

            //Obtener clave descifrada
            byte [] bytesClaveDES = cifradorRSA.doFinal(claveDES_cifrada);

            //Crear cifradorDES
            Cipher cifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding");
            SecretKey claveDES = new SecretKeySpec(bytesClaveDES, "DES");
            cifradorDES.init(Cipher.DECRYPT_MODE, claveDES);

            //Leer examen cifrado
            byte [] examenCifrado = p.getContenidoBloque("Examen Cifrado");
            examen_claro = cifradorDES.doFinal(examenCifrado);

            //Obtener Examen limpio
            File file = new File(args[1]);
            try {
                FileOutputStream out = new FileOutputStream(file);
                out.write(examen_claro);
                out.close();
            }catch (Exception e){
                e.printStackTrace();
            }
            
            System.out.println("Examen en limpio obtenido");

            //Comprobar FIRMA DIGITAL
            //Recuperar clave publica del alumno
            byte[] bufferPub = Files.readAllBytes(Paths.get(args[3]));
            X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
            PublicKey clavePublica = keyFactoryRSA.generatePublic(clavePublicaSpec);
            System.out.println("Clave publica del alumno recuperada");

            //Leemos el hash para descifrar
            byte [] firmaCifrada = p.getContenidoBloque("Hash Alumno");

            //Verificar firma digital del alumno
            Signature firmaAlumno = Signature.getInstance("MD5withRSA");
            firmaAlumno.initVerify(clavePublica);
            firmaAlumno.update(examenCifrado);
            firmaAlumno.update(claveDES_cifrada);
            if(firmaAlumno.verify(firmaCifrada)){
                System.out.println("Firma digital correcta!!");
            } else {
                System.out.println("Error en la firma digital.");
            }

            //Recuperar clave publica de la autoridad de sellado
            byte[] bufferSellado = Files.readAllBytes(Paths.get(args[4]));
            X509EncodedKeySpec claveSelladoSpec = new X509EncodedKeySpec(bufferSellado);
            PublicKey claveSellado = keyFactoryRSA.generatePublic(claveSelladoSpec);
            System.out.println("Clave publica de la autoridad de sellado");

            byte [] fechaHora = p.getContenidoBloque("Fecha Hora");
            byte [] sellado = p.getContenidoBloque("Sellado Tiempo");

            //Verificar sellado de la autoridad de sellado
            Signature selladoTiempo = Signature.getInstance("MD5withRSA");
            selladoTiempo.initVerify(claveSellado);
            selladoTiempo.update(fechaHora);
            selladoTiempo.update(examenCifrado);
            selladoTiempo.update(claveDES_cifrada);
            selladoTiempo.update(firmaCifrada);
            if (selladoTiempo.verify(sellado)) {
                System.out.println("Sellado correcto!!");
            } else {
                System.out.println("Error en el sellado.");
            }


        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException
                | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException | IOException e1) {
            e1.printStackTrace();
        } catch (SignatureException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }
}
