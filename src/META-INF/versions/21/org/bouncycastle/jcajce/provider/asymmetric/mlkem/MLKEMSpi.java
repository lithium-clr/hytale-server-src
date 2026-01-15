package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KEMSpi;
import javax.crypto.KEMSpi.DecapsulatorSpi;
import javax.crypto.KEMSpi.EncapsulatorSpi;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

public class MLKEMSpi implements KEMSpi {
   @Override
   public EncapsulatorSpi engineNewEncapsulator(PublicKey var1, AlgorithmParameterSpec var2, SecureRandom var3) throws InvalidAlgorithmParameterException, InvalidKeyException {
      if (!(var1 instanceof BCMLKEMPublicKey)) {
         throw new InvalidKeyException("unsupported key");
      } else {
         if (var2 == null) {
            var2 = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
         }

         if (!(var2 instanceof KTSParameterSpec)) {
            throw new InvalidAlgorithmParameterException("MLKEM can only accept KTSParameterSpec");
         } else {
            if (var3 == null) {
               var3 = new SecureRandom();
            }

            return new MLKEMEncapsulatorSpi((BCMLKEMPublicKey)var1, (KTSParameterSpec)var2, var3);
         }
      }
   }

   @Override
   public DecapsulatorSpi engineNewDecapsulator(PrivateKey var1, AlgorithmParameterSpec var2) throws InvalidAlgorithmParameterException, InvalidKeyException {
      if (!(var1 instanceof BCMLKEMPrivateKey)) {
         throw new InvalidKeyException("unsupported key");
      } else {
         if (var2 == null) {
            var2 = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
         }

         if (!(var2 instanceof KTSParameterSpec)) {
            throw new InvalidAlgorithmParameterException("MLKEM can only accept KTSParameterSpec");
         } else {
            return new MLKEMDecapsulatorSpi((BCMLKEMPrivateKey)var1, (KTSParameterSpec)var2);
         }
      }
   }
}
