package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

class HKDF {
   private static final String PREFIX = "org.bouncycastle.jcajce.provider.kdf.hkdf.";

   public static class Mappings extends AlgorithmProvider {
      @Override
      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("KDF.HKDF", "org.bouncycastle.jcajce.provider.kdf.hkdf.HKDFSpi");
         var1.addAlgorithm("KDF.HKDF-SHA256", "org.bouncycastle.jcajce.provider.kdf.hkdf.HKDFSpi$HKDFwithSHA256");
         var1.addAlgorithm("KDF.HKDF-SHA384", "org.bouncycastle.jcajce.provider.kdf.hkdf.HKDFSpi$HKDFwithSHA384");
         var1.addAlgorithm("KDF.HKDF-SHA512", "org.bouncycastle.jcajce.provider.kdf.hkdf.HKDFSpi$HKDFwithSHA512");
      }
   }
}
