import Excepciones.ProtocolException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.awt.FontFormatException;
import java.io.PrintStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Random;
import javax.crypto.SecretKey;
import utils.Seguridad;
import utils.Transformacion;
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
            String seleccionStr;
            int seleccion;

            System.out.println("Ingrese el numero del algoritmo para cifrado simetrico: \n\t1. DES \n\t2. AES"
            		+ "\n\t3. Blowfish\n\t4. RC4 ");
            seleccionStr = stdIn.readLine();
            seleccion = Integer.parseInt(seleccionStr);
            switch (seleccion){
                case 1:
                    respuestaAServidor += "DES:";
                    break;
                case 2:
                    respuestaAServidor += "AES:";
                    break;
                case 3:
                    respuestaAServidor += "Blowfish:";
                    break;
                case 4:
                    respuestaAServidor += "RC4:";
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
                    break;
                case 2:
                    respuestaAServidor += "HMACSHA1";
                    break;
                case 3:
                    respuestaAServidor += "HMACSHA256";
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
            X509Certificate certificadoCliente;
            
            KeyPair keyPair = Seguridad.generateRSAKeyPair();
            

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
              write(writer, certStr);
            }
            catch (Exception e)
            {
              e.printStackTrace();
            }
            



        }catch (IOException e){
            e.printStackTrace();
        }catch (ProtocolException e){
            System.out.println(e.getMessage());
        }
    }
}
