package org.bouncycastle.jcajce.provider.kdf.scrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jcajce.spec.ScryptParameterSpec;
import org.bouncycastle.util.Arrays;

class ScryptSpi extends KDFSpi {
   protected ScryptSpi(KDFParameters var1) throws InvalidAlgorithmParameterException {
      super(requireNull(var1, "Scrypt does not support parameters"));
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
      if (!(var1 instanceof ScryptParameterSpec)) {
         throw new InvalidAlgorithmParameterException("SCrypt requires an SCryptParameterSpec as derivation parameters");
      } else {
         ScryptKeySpec var2 = (ScryptKeySpec)var1;
         char[] var3 = var2.getPassword();
         byte[] var4 = var2.getSalt();
         int var5 = var2.getCostParameter();
         int var6 = var2.getBlockSize();
         int var7 = var2.getParallelizationParameter();
         int var8 = var2.getKeyLength();
         if (var4 == null) {
            throw new InvalidAlgorithmParameterException("Salt S must be provided.");
         } else if (var5 <= 1) {
            throw new InvalidAlgorithmParameterException("Cost parameter N must be > 1.");
         } else if (var8 <= 0) {
            throw new InvalidAlgorithmParameterException("positive key length required: " + var8);
         } else {
            byte[] var9 = SCrypt.generate(PasswordConverter.UTF8.convert(var3), var4, var5, var6, var7, var8 / 8);
            Arrays.clear(var3);
            return var9;
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

   public static class ScryptWithUTF8 extends ScryptSpi {
      public ScryptWithUTF8(KDFParameters var1) throws InvalidAlgorithmParameterException {
         super(var1);
      }
   }
}
