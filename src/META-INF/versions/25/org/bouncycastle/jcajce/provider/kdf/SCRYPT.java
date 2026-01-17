package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

class SCRYPT {
   private static final String PREFIX = "org.bouncycastle.jcajce.provider.kdf.scrypt.";

   public static class Mappings extends AlgorithmProvider {
      @Override
      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("KDF.SCRYPT", "org.bouncycastle.jcajce.provider.kdf.scrypt.ScryptSpi$ScryptWithUTF8");
      }
   }
}
