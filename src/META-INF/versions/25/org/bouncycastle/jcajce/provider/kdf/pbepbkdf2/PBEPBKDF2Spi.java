package org.bouncycastle.jcajce.provider.kdf.pbepbkdf2;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

class PBEPBKDF2Spi extends KDFSpi {
   final PasswordConverter pwdConverter;
   final PKCS5S2ParametersGenerator generator;

   protected PBEPBKDF2Spi(KDFParameters var1) throws InvalidAlgorithmParameterException {
      this(var1, new SHA1Digest(), PasswordConverter.UTF8);
   }

   protected PBEPBKDF2Spi(KDFParameters var1, Digest var2) throws InvalidAlgorithmParameterException {
      this(var1, var2, PasswordConverter.UTF8);
   }

   protected PBEPBKDF2Spi(KDFParameters var1, Digest var2, PasswordConverter var3) throws InvalidAlgorithmParameterException {
      super(requireNull(var1, "PBEPBKDF2 does not support parameters"));
      this.pwdConverter = var3;
      this.generator = new PKCS5S2ParametersGenerator(var2);
   }

   @Override
   protected KDFParameters engineGetParameters() {
      return null;
   }

   @Override
   protected SecretKey engineDeriveKey(String var1, AlgorithmParameterSpec var2) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
      byte[] var3 = this.engineDeriveData(var2);
      return new SecretKeySpec(var3, var1);
   }

   @Override
   protected byte[] engineDeriveData(AlgorithmParameterSpec var1) throws InvalidAlgorithmParameterException {
      if (!(var1 instanceof PBEKeySpec var2)) {
         throw new InvalidAlgorithmParameterException("Invalid AlgorithmParameterSpec provided");
      } else {
         char[] var3 = var2.getPassword();
         byte[] var4 = var2.getSalt();
         int var5 = var2.getIterationCount();
         int var6 = var2.getKeyLength();
         if (var3 != null && var4 != null) {
            this.generator.init(this.pwdConverter.convert(var3), var4, var5);
            KeyParameter var7 = (KeyParameter)this.generator.generateDerivedParameters(var6);
            byte[] var8 = var7.getKey();
            Arrays.fill(var3, '\u0000');
            return var8;
         } else {
            throw new InvalidAlgorithmParameterException("Password and salt cannot be null");
         }
      }
   }

   private static KDFParameters requireNull(KDFParameters var0, String var1) throws InvalidAlgorithmParameterException {
      if (var0 != null) {
         throw new InvalidAlgorithmParameterException(var1);
      } else {
         return null;
      }
   }

   public static class PBKDF2with8BIT extends PBEPBKDF2Spi {
      public PBKDF2with8BIT(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA1Digest(), PasswordConverter.ASCII);
      }

      public PBKDF2with8BIT() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withGOST3411 extends PBEPBKDF2Spi {
      public PBKDF2withGOST3411(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new GOST3411Digest());
      }

      public PBKDF2withGOST3411() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withSHA224 extends PBEPBKDF2Spi {
      public PBKDF2withSHA224(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA224Digest());
      }

      public PBKDF2withSHA224() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withSHA256 extends PBEPBKDF2Spi {
      public PBKDF2withSHA256(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA256Digest());
      }

      public PBKDF2withSHA256() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withSHA384 extends PBEPBKDF2Spi {
      public PBKDF2withSHA384(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA384Digest());
      }

      public PBKDF2withSHA384() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withSHA3_224 extends PBEPBKDF2Spi {
      public PBKDF2withSHA3_224(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA3Digest(224));
      }

      public PBKDF2withSHA3_224() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withSHA3_256 extends PBEPBKDF2Spi {
      public PBKDF2withSHA3_256(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA3Digest(256));
      }

      public PBKDF2withSHA3_256() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withSHA3_384 extends PBEPBKDF2Spi {
      public PBKDF2withSHA3_384(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA3Digest(384));
      }

      public PBKDF2withSHA3_384() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withSHA3_512 extends PBEPBKDF2Spi {
      public PBKDF2withSHA3_512(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA3Digest(512));
      }

      public PBKDF2withSHA3_512() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withSHA512 extends PBEPBKDF2Spi {
      public PBKDF2withSHA512(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA512Digest());
      }

      public PBKDF2withSHA512() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withSHA512_224 extends PBEPBKDF2Spi {
      public PBKDF2withSHA512_224(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA512tDigest(224));
      }

      public PBKDF2withSHA512_224() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withSHA512_256 extends PBEPBKDF2Spi {
      public PBKDF2withSHA512_256(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA512tDigest(256));
      }

      public PBKDF2withSHA512_256() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withSM3 extends PBEPBKDF2Spi {
      public PBKDF2withSM3(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SM3Digest());
      }

      public PBKDF2withSM3() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class PBKDF2withUTF8 extends PBEPBKDF2Spi {
      public PBKDF2withUTF8(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA1Digest());
      }

      public PBKDF2withUTF8() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }
}
