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
    public final static void main(String[] args) { // <nombre_paquete.paquete> <alumno.publica> <autoridad.privada>
        // Anadir provider  (el provider por defecto no soporta RSA)
		Security.addProvider(new BouncyCastleProvider()); // Cargar el provider BC

        try {
            // Recuperar clave publica del alumno
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
            PublicKey clavePublica = recuperarClavePublicaAlumno(args[1], keyFactoryRSA);
            System.out.println("Clave publica del alumno obtenida");

            //Cargar datos del paquete necesarios
            Paquete p = new Paquete(args[0]);
            byte[] firmaCifrada = p.getContenidoBloque("Hash Alumno");
            byte[] examenCifrado = p.getContenidoBloque("Examen Cifrado");
            byte[] claveDES_cifrada = p.getContenidoBloque("Clave Cifrada");
            System.out.println("Bloques necesarios del paquete cargados");

            //Comprobar FIRMA DIGITAL del alumno
            if(esFirmaAlumnoValida(clavePublica, firmaCifrada, examenCifrado, claveDES_cifrada)){
                //Recuperar clave privada de la autoridad
                PrivateKey clavePrivada = recuperarClavePrivadaAutoridad(args[2], keyFactoryRSA);
                System.out.println("Clave privada de la autoridad obtenida");

                Date fechaHora = new Date();
                //Firma de la autoridad de sellado
                byte[] hashSellado = realizarSellado(firmaCifrada, examenCifrado, claveDES_cifrada, clavePrivada, fechaHora);
                System.out.println("Sellado de tiempo realizado");

                sobreescribirPaquete(args[0], p, fechaHora, hashSellado);
                System.out.println("Paquete sobreescrito con los 2 bloques del sellado");

            } else {
                System.err.println("ERROR: FIRMA ALUMNO NO VALIDA, NO SE HA LLEVADO A CABO EL SELLADO");
            }

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException
                | SignatureException | IOException e) {
            e.printStackTrace();
        }
    }

    private static void sobreescribirPaquete(String nombrePaquete, Paquete p, Date fechaHora, byte[] hashSellado) {
        p.anadirBloque("Fecha Hora", fechaHora.toString().getBytes());
        System.out.println("Fecha del sellado añadida al paquete");
        p.anadirBloque("Sellado Tiempo", hashSellado);
        System.out.println("Sello añadido al paquete");
        p.escribirPaquete(nombrePaquete);
    }

    private static boolean esFirmaAlumnoValida(PublicKey clavePublica, byte[] firmaCifrada, byte[] examenCifrado,
            byte[] claveDES_cifrada) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
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

    private static PublicKey recuperarClavePublicaAlumno(String clave, KeyFactory keyFactoryRSA)
            throws IOException, InvalidKeySpecException {
        byte[] bufferPub = Files.readAllBytes(Paths.get(clave));
        X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
        PublicKey clavePublica = keyFactoryRSA.generatePublic(clavePublicaSpec);
        return clavePublica;
    }

    private static PrivateKey recuperarClavePrivadaAutoridad(String clave, KeyFactory keyFactoryRSA)
            throws IOException, InvalidKeySpecException {
        byte[] bufferPriv = Files.readAllBytes(Paths.get(clave));
        PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
        PrivateKey clavePrivada = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
        return clavePrivada;
    }

    private static byte[] realizarSellado(byte[] firmaCifrada, byte[] examenCifrado, byte[] claveDES_cifrada,
            PrivateKey clavePrivada, Date fechaHora)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature selladoTiempo = Signature.getInstance("MD5withRSA");
        selladoTiempo.initSign(clavePrivada);
        System.out.println("Fecha y hora actuales: " + fechaHora);
        selladoTiempo.update(fechaHora.toString().getBytes());
        selladoTiempo.update(examenCifrado);
        selladoTiempo.update(claveDES_cifrada);
        selladoTiempo.update(firmaCifrada);
        byte [] hashSellado = selladoTiempo.sign();
        return hashSellado;
    }
}
