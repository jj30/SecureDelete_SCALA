import java.nio.ByteBuffer
import java.security.{MessageDigest, SecureRandom, Security}
import java.util.logging.Logger
import javax.crypto.{Cipher, SecretKey, SecretKeyFactory}
import javax.xml.bind.DatatypeConverter
import javax.crypto.spec.{IvParameterSpec, PBEKeySpec, SecretKeySpec}
import org.bouncycastle.jce.provider.BouncyCastleProvider;

object BaseCrypto {
    /*
    usage
    DatatypeConverter.parseHexBinary("000086003D")
    res19: Array[Byte] = Array(0, 0, -122, 0, 61)

    DatatypeConverter.printHexBinary(Array(0,0,-122,0,61))
    res20: String = 000086003D

    */

    var SALT_LENGTH : Integer = 20;
    var IV_LENGTH : Integer = 16;
    var PBE_ITERATION_COUNT : Integer = 100;

    var RANDOM_ALGORITHM : String = "SHA1PRNG";
    var HASH_ALGORITHM : String = "SHA-512";
    var PBE_ALGORITHM : String = "PBEWithSHA256And256BitAES-CBC-BC";
    var CIPHER_ALGORITHM : String = "AES/CBC/PKCS5Padding";
    var SECRET_KEY_ALGORITHM : String = "AES";

    def generateIv : Array[Byte] = {
      val r = SecureRandom.getInstance(RANDOM_ALGORITHM)
      var bytePW : Array[Byte] = new Array[Byte](IV_LENGTH)
      r.nextBytes(bytePW)
      bytePW
    }

    def encrypt(secret : SecretKey, cleartext : String) : String = {
      try {
        val iv : Array[Byte] = generateIv;
        val ivHex : String = DatatypeConverter.printHexBinary(iv);
        val ivspec : IvParameterSpec = new IvParameterSpec(iv);

        Security.addProvider(new BouncyCastleProvider)
        val provider = new BouncyCastleProvider
        val encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM, provider);

        encryptionCipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
        val encryptedText : Array[Byte] = encryptionCipher.doFinal(cleartext.getBytes("UTF-8"));
        val encryptedHex : String = DatatypeConverter.printHexBinary(encryptedText);

        return ivHex + encryptedHex;

      } catch {
        case e: Exception => "encrypt: " + e.getMessage()
      }
    }

    def decrypt(secret : SecretKey, encrypted : String) : String = {
      try {
        Security.addProvider(new BouncyCastleProvider)
        val provider = new BouncyCastleProvider

        val decryptionCipher : Cipher = Cipher.getInstance(CIPHER_ALGORITHM, provider);
        val ivHex : String = encrypted.substring(0, IV_LENGTH * 2);
        val encryptedHex : String = encrypted.substring(IV_LENGTH * 2);
        val ivspec : IvParameterSpec = new IvParameterSpec(DatatypeConverter.parseHexBinary(ivHex));

        decryptionCipher.init(Cipher.DECRYPT_MODE, secret, ivspec);
        val decryptedText : Array[Byte] = decryptionCipher.doFinal(DatatypeConverter.parseHexBinary(encryptedHex));
        val decrypted : String = new String(decryptedText, "UTF-8");

        return decrypted;
      } catch {
        case e: Exception => "Problem?"
      }
    }

    def getSecretKey(password : String, salt : String) : SecretKey = {
      Security.addProvider(new BouncyCastleProvider)
      val provider = new BouncyCastleProvider

      val pbeKeySpec : PBEKeySpec = new PBEKeySpec(password.toCharArray(), DatatypeConverter.parseHexBinary(salt), PBE_ITERATION_COUNT, 256);
      val factory : SecretKeyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM, provider);
      val tmp : SecretKey = factory.generateSecret(pbeKeySpec);
      val secret : SecretKey = new SecretKeySpec(tmp.getEncoded(), SECRET_KEY_ALGORITHM);
      return secret;
    }

    def getHash (password : String, salt : String) : String = {
      try {
        Security.addProvider(new BouncyCastleProvider)
        val provider = new BouncyCastleProvider

        val input : String = password + salt;
        val md : MessageDigest = MessageDigest.getInstance(HASH_ALGORITHM, provider);
        val out : Array[Byte] = md.digest(input.getBytes("UTF-8"));
        DatatypeConverter.printHexBinary(out);
      } catch {
        case e: Exception => "Problem? " + e.getMessage()
      }
    }

    def generateSalt() : String = {
      try {
        val random : SecureRandom = SecureRandom.getInstance(RANDOM_ALGORITHM);
        var salt : Array[Byte] = new Array[Byte](SALT_LENGTH);

        random.nextBytes(salt);
        val saltHex : String = DatatypeConverter.printHexBinary(salt);
        saltHex;
      } catch {
        case e: Exception => "Problem? " + e.getMessage()
      }
    }

    def encryptContent (content : String, def_pass : String, salt : String) : String = {
      try {
        val key = getSecretKey(def_pass, salt);
        val encryptedContent = encrypt(key, content);
        encryptedContent;
      } catch {
        case e: Exception => "encryptContent:  " + e.getMessage()
      }
    }

    def decryptContent(cryptedContent : String, def_pass : String, salt : String) : String = {
      try {
        val key = getSecretKey(def_pass, salt);
        val content = decrypt(key, cryptedContent);
        content;
      } catch {
        case e: Exception => "decryptContent:  " + e.getMessage()
      }
    }
}