package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.util.Arrays;
import java.util.Objects;
import javax.crypto.DecapsulateException;
import javax.crypto.SecretKey;
import javax.crypto.KEMSpi.DecapsulatorSpi;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.jcajce.provider.util.KdfUtil;

public class MLKEMDecapsulatorSpi implements DecapsulatorSpi {
   BCMLKEMPrivateKey privateKey;
   KTSParameterSpec parameterSpec;
   MLKEMExtractor kemExt;

   public MLKEMDecapsulatorSpi(BCMLKEMPrivateKey var1, KTSParameterSpec var2) {
      this.privateKey = var1;
      this.parameterSpec = var2;
      this.kemExt = new MLKEMExtractor(var1.getKeyParams());
   }

   @Override
   public SecretKey engineDecapsulate(byte[] var1, int var2, int var3, String var4) throws DecapsulateException {
      Objects.checkFromToIndex(var2, var3, this.engineSecretSize());
      Objects.requireNonNull(var4, "null algorithm");
      Objects.requireNonNull(var1, "null encapsulation");
      if (var1.length != this.engineEncapsulationSize()) {
         throw new DecapsulateException("incorrect encapsulation size");
      } else {
         if (!this.parameterSpec.getKeyAlgorithmName().equals("Generic") && var4.equals("Generic")) {
            var4 = this.parameterSpec.getKeyAlgorithmName();
         }

         if (!this.parameterSpec.getKeyAlgorithmName().equals("Generic") && !this.parameterSpec.getKeyAlgorithmName().equals(var4)) {
            throw new UnsupportedOperationException(this.parameterSpec.getKeyAlgorithmName() + " does not match " + var4);
         } else {
            boolean var5 = this.parameterSpec.getKdfAlgorithm() != null;
            byte[] var6 = this.kemExt.extractSecret(var1);
            byte[] var7 = Arrays.copyOfRange(KdfUtil.makeKeyBytes(this.parameterSpec, var6), var2, var3);
            return new SecretKeySpec(var7, var4);
         }
      }
   }

   @Override
   public int engineSecretSize() {
      return this.parameterSpec.getKeySize() / 8;
   }

   @Override
   public int engineEncapsulationSize() {
      return this.kemExt.getEncapsulationLength();
   }
}
