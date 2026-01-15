package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import java.security.SecureRandom;
import java.util.Objects;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEMSpi.EncapsulatorSpi;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.jcajce.provider.util.KdfUtil;
import org.bouncycastle.util.Arrays;

class SNTRUPrimeEncapsulatorSpi implements EncapsulatorSpi {
   private final BCSNTRUPrimePublicKey publicKey;
   private final KTSParameterSpec parameterSpec;
   private final SNTRUPrimeKEMGenerator kemGen;

   public SNTRUPrimeEncapsulatorSpi(BCSNTRUPrimePublicKey var1, KTSParameterSpec var2, SecureRandom var3) {
      this.publicKey = var1;
      this.parameterSpec = var2;
      this.kemGen = new SNTRUPrimeKEMGenerator(var3);
   }

   @Override
   public Encapsulated engineEncapsulate(int var1, int var2, String var3) {
      Objects.checkFromToIndex(var1, var2, this.engineSecretSize());
      Objects.requireNonNull(var3, "null algorithm");
      if (!this.parameterSpec.getKeyAlgorithmName().equals("Generic") && var3.equals("Generic")) {
         var3 = this.parameterSpec.getKeyAlgorithmName();
      }

      if (!this.parameterSpec.getKeyAlgorithmName().equals("Generic") && !this.parameterSpec.getKeyAlgorithmName().equals(var3)) {
         throw new UnsupportedOperationException(this.parameterSpec.getKeyAlgorithmName() + " does not match " + var3);
      } else {
         SecretWithEncapsulation var4 = this.kemGen.generateEncapsulated(this.publicKey.getKeyParams());
         byte[] var5 = var4.getEncapsulation();
         byte[] var6 = var4.getSecret();
         byte[] var7 = Arrays.copyOfRange(KdfUtil.makeKeyBytes(this.parameterSpec, var6), var1, var2);
         return new Encapsulated(new SecretKeySpec(var7, var3), var5, null);
      }
   }

   @Override
   public int engineSecretSize() {
      return this.parameterSpec.getKeySize() / 8;
   }

   @Override
   public int engineEncapsulationSize() {
      return this.publicKey.getKeyParams().getParameters().getRoundedPolynomialBytes() + 32;
   }
}
