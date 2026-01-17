package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import java.util.Objects;
import javax.crypto.DecapsulateException;
import javax.crypto.SecretKey;
import javax.crypto.KEMSpi.DecapsulatorSpi;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.jcajce.provider.util.KdfUtil;
import org.bouncycastle.util.Arrays;

class SNTRUPrimeDecapsulatorSpi implements DecapsulatorSpi {
   BCSNTRUPrimePrivateKey privateKey;
   KTSParameterSpec parameterSpec;
   SNTRUPrimeKEMExtractor kemExt;

   public SNTRUPrimeDecapsulatorSpi(BCSNTRUPrimePrivateKey var1, KTSParameterSpec var2) {
      this.privateKey = var1;
      this.parameterSpec = var2;
      this.kemExt = new SNTRUPrimeKEMExtractor(var1.getKeyParams());
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
            byte[] var5 = this.kemExt.extractSecret(var1);
            byte[] var6 = Arrays.copyOfRange(KdfUtil.makeKeyBytes(this.parameterSpec, var5), var2, var3);
            return new SecretKeySpec(var6, var4);
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
