package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEMSpi.EncapsulatorSpi;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.jcajce.provider.util.KdfUtil;

public class MLKEMEncapsulatorSpi implements EncapsulatorSpi {
   private final BCMLKEMPublicKey publicKey;
   private final KTSParameterSpec parameterSpec;
   private final MLKEMGenerator kemGen;

   public MLKEMEncapsulatorSpi(BCMLKEMPublicKey var1, KTSParameterSpec var2, SecureRandom var3) {
      this.publicKey = var1;
      this.parameterSpec = var2;
      this.kemGen = new MLKEMGenerator(var3);
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
         boolean var4 = this.parameterSpec.getKdfAlgorithm() != null;
         SecretWithEncapsulation var5 = this.kemGen.generateEncapsulated(this.publicKey.getKeyParams());
         byte[] var6 = var5.getEncapsulation();
         byte[] var7 = var5.getSecret();
         byte[] var8 = Arrays.copyOfRange(KdfUtil.makeKeyBytes(this.parameterSpec, var7), var1, var2);
         return new Encapsulated(new SecretKeySpec(var8, var3), var6, null);
      }
   }

   @Override
   public int engineSecretSize() {
      return this.parameterSpec.getKeySize() / 8;
   }

   @Override
   public int engineEncapsulationSize() {
      String var1 = this.publicKey.getKeyParams().getParameters().getName();
      switch (var1) {
         case "ML-KEM-512":
            return 768;
         case "ML-KEM-768":
            return 1088;
         case "ML-KEM-1024":
            return 1568;
         default:
            return -1;
      }
   }
}
