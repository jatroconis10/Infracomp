package utils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Seguridad
{
  public static final String RSA = "RSA";
  public static final String HMACMD5 = "HMACMD5";
  public static final String HMACSHA1 = "HMACSHA1";
  public static final String HMACSHA256 = "HMACSHA256";
  public static final String RC4 = "RC4";
  public static final String BLOWFISH = "Blowfish";
  public static final String AES = "AES";
  public static final String DES = "DES";
  
  public Seguridad() {}
  
  public static byte[] symmetricEncryption(byte[] msg, Key key, String algo)
    throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
  {
    algo = 
      algo + ((algo.equals("DES")) || (algo.equals("AES")) ? "/ECB/PKCS5Padding" : "");
    Cipher decifrador = Cipher.getInstance(algo);
    decifrador.init(1, key);
    return decifrador.doFinal(msg);
  }
 
  public static byte[] symmetricDecryption(byte[] msg, Key key, String algo)
    throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
  {
    algo = 
      algo + ((algo.equals("DES")) || (algo.equals("AES")) ? "/ECB/PKCS5Padding" : "");
    Cipher decifrador = Cipher.getInstance(algo);
    decifrador.init(2, key);
    return decifrador.doFinal(msg);
  }
  
  public static byte[] asymmetricEncryption(byte[] msg, Key key, String algo)
    throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException
  {
    Cipher decifrador = Cipher.getInstance(algo);
    decifrador.init(1, key);
    return decifrador.doFinal(msg);
  }
  
  public static byte[] asymmetricDecryption(byte[] msg, Key key, String algo)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
  {
    Cipher decifrador = Cipher.getInstance(algo);
    decifrador.init(2, key);
    return decifrador.doFinal(msg);
  }
  
  public static byte[] hmacDigest(byte[] msg, Key key, String algo)
    throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, UnsupportedEncodingException
  {
    Mac mac = Mac.getInstance(algo);
    mac.init(key);
    
    byte[] bytes = mac.doFinal(msg);
    return bytes;
  }
 
  public static boolean verificarIntegridad(byte[] msg, Key key, String algo, byte[] hash)
    throws Exception
  {
    byte[] nuevo = hmacDigest(msg, key, algo);
    if (nuevo.length != hash.length) {
      return false;
    }
    for (int i = 0; i < nuevo.length; i++) {
      if (nuevo[i] != hash[i]) return false;
    }
    return true;
  }
  
  public static SecretKey keyGenGenerator(String algoritmo)
    throws NoSuchAlgorithmException, NoSuchProviderException
  {
    int tamLlave = 0;
    if (algoritmo.equals("DES")) {
      tamLlave = 64;
    } else if (algoritmo.equals("AES")) {
      tamLlave = 128;
    } else if (algoritmo.equals("Blowfish")) {
      tamLlave = 128;
    } else if (algoritmo.equals("RC4")) {
      tamLlave = 128;
    }
    if (tamLlave == 0) { throw new NoSuchAlgorithmException();
    }
    

    KeyGenerator keyGen = KeyGenerator.getInstance(algoritmo, "BC");
    keyGen.init(tamLlave);
    SecretKey key = keyGen.generateKey();
    return key;
  }
 
  public static X509Certificate generateV3Certificate(KeyPair pair)
    throws Exception
  {
    PublicKey subPub = pair.getPublic();
    PrivateKey issPriv = pair.getPrivate();
    PublicKey issPub = pair.getPublic();
    
    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
    X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
      new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), 
      new BigInteger(128, new SecureRandom()), 
      new Date(System.currentTimeMillis()), 
      new Date(System.currentTimeMillis() + 8640000000L), 
      new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), subPub);
    
    v3CertGen.addExtension(
      X509Extension.subjectKeyIdentifier, 
      false, 
      extUtils.createSubjectKeyIdentifier(subPub));
    
    v3CertGen.addExtension(
      X509Extension.authorityKeyIdentifier, 
      false, 
      extUtils.createAuthorityKeyIdentifier(issPub));
    
    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(new JcaContentSignerBuilder("MD5withRSA").setProvider("BC").build(issPriv)));
  }
  public static KeyPair generateRSAKeyPair()
    throws NoSuchAlgorithmException
  {
    KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
    kpGen.initialize(1024, new SecureRandom());
    return kpGen.generateKeyPair();
  }
}