package org.bouncycastle.jcajce.provider.kdf.hkdf;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.HKDFParameterSpec.Extract;
import javax.crypto.spec.HKDFParameterSpec.ExtractThenExpand;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.spec.HKDFParameterSpec;

class HKDFSpi extends KDFSpi {
   protected HKDFBytesGenerator hkdf;

   public HKDFSpi(KDFParameters var1, Digest var2) throws InvalidAlgorithmParameterException {
      super(requireNull(var1, "HKDF does not support parameters"));
      this.hkdf = new HKDFBytesGenerator(var2);
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
      if (var1 != null && (var1 instanceof HKDFParameterSpec || var1 instanceof javax.crypto.spec.HKDFParameterSpec)) {
         Object var2 = null;
         int var3 = 0;
         if (var1 instanceof ExtractThenExpand var13) {
            List var15 = var13.ikms();
            List var16 = var13.salts();
            var2 = new HKDFParameters(((SecretKey)var15.get(0)).getEncoded(), ((SecretKey)var16.get(0)).getEncoded(), var13.info());
            var3 = var13.length();
            this.hkdf.init((DerivationParameters)var2);
            byte[] var7 = new byte[var3];
            this.hkdf.generateBytes(var7, 0, var3);
            return var7;
         } else if (var1 instanceof Extract var12) {
            List var14 = var12.ikms();
            List var6 = var12.salts();
            return this.hkdf.extractPRK(((SecretKey)var6.get(0)).getEncoded(), ((SecretKey)var14.get(0)).getEncoded());
         } else if (var1 instanceof HKDFParameterSpec var4) {
            var2 = new HKDFParameters(var4.getIKM(), var4.getSalt(), var4.getInfo());
            var3 = var4.getOutputLength();
            this.hkdf.init((DerivationParameters)var2);
            byte[] var5 = new byte[var3];
            this.hkdf.generateBytes(var5, 0, var3);
            return var5;
         } else {
            throw new InvalidAlgorithmParameterException("invalid HKDFParameterSpec provided");
         }
      } else {
         throw new InvalidAlgorithmParameterException("Invalid AlgorithmParameterSpec provided");
      }
   }

   private static KDFParameters requireNull(KDFParameters var0, String var1) throws InvalidAlgorithmParameterException {
      if (var0 != null) {
         throw new InvalidAlgorithmParameterException(var1);
      } else {
         return null;
      }
   }

   public static class HKDFwithSHA256 extends HKDFSpi {
      public HKDFwithSHA256(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA256Digest());
      }

      public HKDFwithSHA256() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class HKDFwithSHA384 extends HKDFSpi {
      public HKDFwithSHA384(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA384Digest());
      }

      public HKDFwithSHA384() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }

   public static class HKDFwithSHA512 extends HKDFSpi {
      public HKDFwithSHA512(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1, new SHA512Digest());
      }

      public HKDFwithSHA512() throws InvalidAlgorithmParameterException {
         this(null);
      }
   }
}
