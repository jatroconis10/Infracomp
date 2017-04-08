import Excepciones.ProtocolException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import utils.Seguridad;
import utils.Transformacion;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class Main {
	
    public static void main(String[] args) {
        //Definicion de la infromacion para la conexion al socket
        String hostName = "localhost";
        int portNumber  = 8654;
        
        try (
                //Try with resources para que los recursos se cierren al final del try
        		Socket clientSocket = new Socket(hostName, portNumber);
                PrintWriter out =
                        new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in =
                        new BufferedReader(
                                new InputStreamReader(clientSocket.getInputStream()));
                BufferedReader stdIn =
                        new BufferedReader(
                                new InputStreamReader(System.in))
        ){
            String mensajeServidor;
            String respuestaAServidor;

            out.println("HOLA");

            mensajeServidor = in.readLine();
            if(!mensajeServidor.equals("OK")){
                throw new ProtocolException("Se esperaba OK pero se reicibio: " + mensajeServidor);
            }

            //Se pregunta al cliente los algoritmos que desea usar
            respuestaAServidor = "ALGORITMOS:";
            String[] algCifrado = new String[3];
            String seleccionStr;
            int seleccion;

            System.out.println("Ingrese el numero del algoritmo para cifrado simetrico: \n\t1. DES \n\t2. AES"
            		+ "\n\t3. Blowfish\n\t4. RC4 ");
            seleccionStr = stdIn.readLine();
            seleccion = Integer.parseInt(seleccionStr);
            switch (seleccion){
                case 1:
                    respuestaAServidor += "DES:";
                    algCifrado[0] = "DES";
                    break;
                case 2:
                    respuestaAServidor += "AES:";
                    algCifrado[0] = "AES";
                    break;
                case 3:
                    respuestaAServidor += "Blowfish:";
                    algCifrado[0] = "Blowfish";
                    break;
                case 4:
                    respuestaAServidor += "RC4:";
                    algCifrado[0] = "RC4";
                    break;
                default:
                    throw new ProtocolException("Opcion de algoritmo invalida");
            }

            System.out.println("Ingrese el numero del algoritmo para cifrado asimetrico: \n\t1. RSA");
            seleccionStr = stdIn.readLine();
            seleccion = Integer.parseInt(seleccionStr);
            switch (seleccion){
                case 1:
                    respuestaAServidor += "RSA:";
                    algCifrado[1] = "RSA";
                    break;
                default:
                    throw new ProtocolException("Opcion de algoritmo invalida");
            }

            System.out.println("Ingrese el numero del algoritmo de HMAC: \n\t1. HmacMD5\n\t2. HmacSHA1\n\t3. HmacM256");
            seleccionStr = stdIn.readLine();
            seleccion = Integer.parseInt(seleccionStr);
            switch (seleccion){
                case 1:
                    respuestaAServidor += "HMACMD5";
                    algCifrado[2] = "HMACMD5";
                    break;
                case 2:
                    respuestaAServidor += "HMACSHA1";
                    algCifrado[2] = "HMACSHA1";
                    break;
                case 3:
                    respuestaAServidor += "HMACSHA256";
                    algCifrado[2] = "HMACSHA256";
                    break;
                default:
                    throw new ProtocolException("Opcion de algoritmo invalida");
            }

            out.println(respuestaAServidor);
            mensajeServidor = in.readLine();
            if(mensajeServidor.equals("ERROR")){
                throw new ProtocolException("El servidor no soporta los algoritmos enviados");
            }
            else if(!mensajeServidor.equals("OK")){
                throw new ProtocolException("El servidor envio un mensaje invalido");
            }

            KeyPair keyPair = null;


            //Generacion y envio del CD
            try
            {
              Security.addProvider(new BouncyCastleProvider());
              KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
              keyGen.initialize(1024);
              keyPair = keyGen.generateKeyPair();
              X509Certificate cert = Seguridad.generateV3Certificate(keyPair);
              StringWriter wr = new StringWriter();
              JcaPEMWriter pemWriter = new JcaPEMWriter(wr);
              pemWriter.writeObject(cert);
              pemWriter.flush();
              pemWriter.close();
              String certStr = wr.toString();
              out.println(certStr);
            }
            catch (Exception e)
            {
              e.printStackTrace();
            }
            X509Certificate certificadoServidor;
            //Lectura del certificado digital del servidor
            try
            {
                mensajeServidor = in.readLine();
                String strToDecode = "";
                strToDecode = strToDecode + mensajeServidor;
                while (!mensajeServidor.equals("-----END CERTIFICATE-----"))
                {
                    strToDecode += mensajeServidor + "\n";
                    mensajeServidor = in.readLine();
                }
                strToDecode = strToDecode + mensajeServidor;
                StringReader rea = new StringReader(strToDecode);
                PemReader pr = new PemReader(rea);
                PemObject pemCertificadoPuntoAtencion = pr.readPemObject();
                X509CertificateHolder certHolder = new X509CertificateHolder(pemCertificadoPuntoAtencion.getContent());
                certificadoServidor = new JcaX509CertificateConverter().getCertificate(certHolder);
                pr.close();
            }
            catch (Exception e)
            {
                e.printStackTrace();
                throw new FontFormatException("Error en el certificado recibido, no se puede decodificar");
            }

            //Generador del reto
            long semilla = 1996L;
            Random rand = new Random(semilla);

            byte[] reto1 = "random1".getBytes();
            rand.nextBytes(reto1);

            String reto1String = new String(reto1);
            System.out.println("Reto: " + reto1String);

            byte[] reto1Cifrado = Seguridad.asymmetricEncryption(reto1,certificadoServidor.getPublicKey(),algCifrado[1]);
            String reto1CifradoString = Transformacion.toHexString(reto1Cifrado);
            out.println(reto1CifradoString);


            TimeUnit.SECONDS.sleep(1);

            //linea sobrante que se tiene que leer antes de leer el primer reto
            in.readLine();
            mensajeServidor = in.readLine();

            System.out.println("Serv: " + mensajeServidor);
            byte[] resReto1Byte = Transformacion.decodificar(mensajeServidor);
            byte[] resReto1Descifrado = Seguridad.asymmetricDecryption(resReto1Byte,keyPair.getPrivate(),algCifrado[1]);
            String resReto1DescifradoString = new String(resReto1Descifrado);
            System.out.println("Serv string :" +  resReto1DescifradoString);
            String comparacion = new String(reto1);


            if(!resReto1DescifradoString.equalsIgnoreCase(comparacion)){
                throw new ProtocolException("No se paso el reto 1");
            }else{
                out.println("OK");
            }

            mensajeServidor = in.readLine();
            byte[] resReto2Bytes = Transformacion.decodificar(mensajeServidor);
            //Decodificar con llaves
            byte[] reto2Descifrado = Seguridad.asymmetricDecryption(resReto2Bytes,keyPair.getPrivate(),algCifrado[1]);
            byte[] reto2Cifrado = Seguridad.asymmetricEncryption(reto2Descifrado,certificadoServidor.getPublicKey(),algCifrado[1]);
            String resReto2String= Transformacion.toHexString(reto2Cifrado);

            out.println(resReto2String);
            mensajeServidor = in.readLine();
            byte[] symKeyBytesCifrada = Transformacion.decodificar(mensajeServidor);
            byte[] symKeyBytes = Seguridad.asymmetricDecryption(symKeyBytesCifrada,keyPair.getPrivate(),algCifrado[1]);
            //llave simetrica
            SecretKey key = new SecretKeySpec(symKeyBytes, 0, symKeyBytes.length, algCifrado[0]);


            System.out.println("Ingrese la cedula que quiere consultar");
            respuestaAServidor = stdIn.readLine();
            byte[] rtaBytes = respuestaAServidor.getBytes();

            byte[] rtaCifrada = Seguridad.symmetricEncryption(rtaBytes, key,algCifrado[0]);

            byte[] digest = Seguridad.hmacDigest(rtaBytes,key, algCifrado[2]);
            byte[] digestCifrado = Seguridad.symmetricEncryption(digest,key,algCifrado[0]);

            String rtaCifradaString = Transformacion.toHexString(rtaCifrada);
            String digestCifradoString = Transformacion.toHexString(digestCifrado);

            respuestaAServidor = rtaCifradaString + ":" + digestCifradoString;

            out.println(respuestaAServidor);
            mensajeServidor = in.readLine();
            String[] respConsulta = mensajeServidor.split(":");

            //Respuesta cifrada con llave simetrica
            byte[] respCifrada = Transformacion.decodificar(respConsulta[0]);
            byte[] respDecifrada = Seguridad.symmetricDecryption(respCifrada, key, algCifrado[0]);
            //Digest de la respuesta cifrado con la llave simetrica
            byte[] respDigestCifrada = Transformacion.decodificar(respConsulta[1]);
            byte[] respDigestDecifrada = Seguridad.symmetricDecryption(respDigestCifrada, key, algCifrado[0]);

            //Verificacion
            boolean ver = Seguridad.verificarIntegridad(respDecifrada,key,algCifrado[2],respDigestDecifrada );

            System.out.println(new String(respCifrada));
            System.out.println(new String(respDigestCifrada));
            if(ver)
                out.println("OK");
            else
                out.println("Error, no se cumple integridad de respuesta");

        }catch (IOException e){
            e.printStackTrace();
        }catch (ProtocolException e){
            System.out.println(e.getMessage());
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
