

package utils;

import javax.xml.bind.DatatypeConverter;

public class Transformacion
{
  public static final String SEPARADOR2 = ";";
  
  public Transformacion() {}
  
  public static String codificar(byte[] b)
  {
    String ret = "";
    for (int i = 0; i < b.length; i++) {
      String g = Integer.toHexString((char)b[i] & 0xFF);
      ret = ret + (g.length() == 1 ? "0" : "") + g;
    }
    return ret;
  }
  

  public static String toHexString(byte[] array)
  {
    return DatatypeConverter.printHexBinary(array);
  }
  
  public static byte[] toByteArray(String s) {
    return DatatypeConverter.parseHexBinary(s);
  }
  
  public static byte[] decodificar(String ss)
  {
    byte[] ret = new byte[ss.length() / 2];
    for (int i = 0; i < ret.length; i++) {
      ret[i] = ((byte)Integer.parseInt(ss.substring(i * 2, (i + 1) * 2), 16));
    }
    return ret;
  }
}

