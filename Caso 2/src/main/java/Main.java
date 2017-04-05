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

public class Main {
	
    public static void main(String[] args) {
        String hostName = "localhost";
        int portNumber  = 8654;
        try (
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

            KeyPair keyPair;
            

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

            try
            {
                mensajeServidor = in.readLine();
                String strToDecode = "";
                strToDecode = strToDecode + mensajeServidor;
                while (!mensajeServidor.equals("-----END CERTIFICATE-----"))
                {
                    strToDecode = strToDecode + mensajeServidor + "\n";
                    mensajeServidor = in.readLine();
                }
                strToDecode = strToDecode + mensajeServidor;
                StringReader rea = new StringReader(strToDecode);
                PemReader pr = new PemReader(rea);
                PemObject pemcertificadoPuntoAtencion = pr.readPemObject();
                X509CertificateHolder certHolder = new X509CertificateHolder(pemcertificadoPuntoAtencion.getContent());
                X509Certificate certificadoCliente = new JcaX509CertificateConverter().getCertificate(certHolder);
                pr.close();
            }
            catch (Exception e)
            {
                e.printStackTrace();
                throw new FontFormatException("Error en el certificado recibido, no se puede decodificar");
            }

            long semilla = 5678L;
            Random rand = new Random(semilla);

            byte[] reto1 = "reto1".getBytes();
            rand.nextBytes(reto1);

            String reto1String = Transformacion.toHexString(reto1);
            out.println("");
            out.println(reto1String);

            mensajeServidor = in.readLine();
            byte[] resReto1Byte = Transformacion.decodificar(mensajeServidor);
            String resReto1String = new String(resReto1Byte);

            if(!resReto1String.equalsIgnoreCase(new String(reto1))){
                throw new ProtocolException("No se paso el reto 1");
            }else{
                out.println("OK");
            }

            mensajeServidor = in.readLine();
            byte[] resReto2Bytes = Transformacion.decodificar(mensajeServidor);
            //Decodificar con llaves
            String resReto2String= Transformacion.toHexString(resReto2Bytes);

            out.println(resReto2String);
            mensajeServidor = in.readLine();
            byte[] symKeyBytes = Transformacion.decodificar(mensajeServidor);

            SecretKey key = new SecretKeySpec(symKeyBytes, 0, symKeyBytes.length, algCifrado[1]);

            respuestaAServidor = "";
            System.out.println("Ingrese la cedula que quiere consultar");
            respuestaAServidor = stdIn.readLine();
            respuestaAServidor += ":" + respuestaAServidor;

            out.println(respuestaAServidor);
            mensajeServidor = in.readLine();
            out.println("OK");

        }catch (IOException e){
            e.printStackTrace();
        }catch (ProtocolException e){
            System.out.println(e.getMessage());
        }catch (Exception e){
            e.printStackTrace();
        }
    }
}
