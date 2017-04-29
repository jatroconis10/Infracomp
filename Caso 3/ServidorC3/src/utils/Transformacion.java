/**
 * 
 */
package utils;

import javax.xml.bind.DatatypeConverter;


/**
 * Clase que contiene metodos static que proveen de metodos de transformacion al protocolo.
 * Infraestructura Computacional 201620
 * Universidad de los Andes.
 * Las tildes han sido eliminadas por cuestiones de compatibilidad.
 * 
 * @author Cristian Brochero 20162
 */
public class Transformacion {

	/**
	 * Separador de los bytes.
	 */
	//public static final String SEPARADOR2 = ";";
	
	/**
	 * Algoritmo de encapsulamiento a enteros. Convierte los bytes de un String a su representacion como enteros.
	 * @param b Los bytes a representar como enteros.
	 * @return EL string construido con la representacion de bytes como enteros.
	 */
	public static String toHexString(byte[] array) {
	    return DatatypeConverter.printHexBinary(array);
	}
	
	/**
	 * Algoritmo que transforma los enteros (en representacion cadena) a bytes.
	 * @param ss El string con los enteros a transformar.
	 * @return Los bytes correspondientes a la entrada.
	 */
	public static byte[] toByteArray(String s) {
	    return DatatypeConverter.parseHexBinary(s);
	}
	
}
