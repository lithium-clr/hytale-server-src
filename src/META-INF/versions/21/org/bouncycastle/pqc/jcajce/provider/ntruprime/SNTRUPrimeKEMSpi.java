package org.bouncycastle.pqc.jcajce.provider.ntruprime;

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

public class SNTRUPrimeKEMSpi implements KEMSpi {
   @Override
   public EncapsulatorSpi engineNewEncapsulator(PublicKey var1, AlgorithmParameterSpec var2, SecureRandom var3) throws InvalidAlgorithmParameterException, InvalidKeyException {
      if (!(var1 instanceof BCSNTRUPrimePublicKey)) {
         throw new InvalidKeyException("unsupported key");
      } else {
         if (var2 == null) {
            var2 = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
         }

         if (!(var2 instanceof KTSParameterSpec)) {
            throw new InvalidAlgorithmParameterException("SNTRUPrime can only accept KTSParameterSpec");
         } else {
            if (var3 == null) {
               var3 = new SecureRandom();
            }

            return new SNTRUPrimeEncapsulatorSpi((BCSNTRUPrimePublicKey)var1, (KTSParameterSpec)var2, var3);
         }
      }
   }

   @Override
   public DecapsulatorSpi engineNewDecapsulator(PrivateKey var1, AlgorithmParameterSpec var2) throws InvalidAlgorithmParameterException, InvalidKeyException {
      if (!(var1 instanceof BCSNTRUPrimePrivateKey)) {
         throw new InvalidKeyException("unsupported key");
      } else {
         if (var2 == null) {
            var2 = new KTSParameterSpec.Builder("Generic", 256).withNoKdf().build();
         }

         if (!(var2 instanceof KTSParameterSpec)) {
            throw new InvalidAlgorithmParameterException("SNTRUPrime can only accept KTSParameterSpec");
         } else {
            return new SNTRUPrimeDecapsulatorSpi((BCSNTRUPrimePrivateKey)var1, (KTSParameterSpec)var2);
         }
      }
   }
}
