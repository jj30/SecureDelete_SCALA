import java.io.{BufferedOutputStream, File, FileOutputStream, InputStream}
import java.nio.ByteBuffer
import java.security.SecureRandom

import org.jasypt.util.binary.BasicBinaryEncryptor


object secdel {
    val base64chars = ('a' to 'z').union('A' to 'Z').union(0 to 9).union(List('/', '+'))


    // http://stackoverflow.com/questions/23976309/trimming-byte-array-when-converting-byte-array-to-string-in-java-scala
    implicit class RichToString( val x: java.nio.ByteBuffer ) extends AnyVal {
      def byteArrayToString() = new String(x.array.takeWhile(_ != 0), "UTF-8")

      def byteArrayToBase64(): String = x.byteArrayToString().filter(base64chars.contains(_))
    }

    class MyInputStream( data: Stream[Byte] ) extends InputStream {
      private val iterator = data.iterator
      override def read(): Int = if (iterator.hasNext) iterator.next else -1
    }

    // http://stackoverflow.com/questions/29978264/how-to-write-the-contents-of-a-scala-stream-to-a-file
    def writeBytes( data : Stream[Byte], file : File ) = {
      val target = new BufferedOutputStream( new FileOutputStream(file) );
      try data.foreach( target.write(_) ) finally target.close;
    }

    def getRandomPW : String = {
      var output : String = ""

      while (output.length() < 10) {
        // val r = scala.util.Random
        val r = SecureRandom.getInstance("SHA1PRNG")
        var bytePW : Array[Byte] = new Array[Byte](1000)
        r.nextBytes(bytePW)
        // get 1000 random bytes into a ByteBuffer
        val preString = ByteBuffer.allocate(1000).put(bytePW)
        // get a random base 64 password at least 10 chars long
        output = preString.byteArrayToBase64()
      }
      output
    }

    // val fileName = "viURNWt.jpg"

    def main( args: Array[String] ): Unit = {
      val fileHandle = new java.io.File(args(0))

      // https://github.com/liufengyun/scala-bug
      val source = scala.io.Source.fromFile(fileHandle, "ISO-8859-1")
      // source = new MyInputStream(dataStream)
      val byteArray = source.map(_.toByte).toArray
      // val byteStream = source.map(_.toByte).toStream

      source.close()

      var binaryEncryptor = new BasicBinaryEncryptor();
      binaryEncryptor.setPassword(getRandomPW);
      val encryptedOut = binaryEncryptor.encrypt(byteArray).toStream
      writeBytes(encryptedOut, fileHandle)

      /* val encSource = scala.io.Source.fromFile("LockJJ.PNG", "ISO-8859-1")
      val encByteArray = encSource.map(_.toByte).toArray
      val plainBytes = binaryEncryptor.decrypt(encByteArray).toStream;

      writeBytes(plainBytes, new File("unLockJJ.PNG"))*/
    }
  }
