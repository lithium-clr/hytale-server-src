package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKeyFactorySpi;

public class NTRU {
   private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.ntru.";

   public static class Mappings extends AsymmetricAlgorithmProvider {
      @Override
      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("KeyFactory.NTRU", "org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKeyFactorySpi");
         var1.addAlgorithm("KeyPairGenerator.NTRU", "org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKeyPairGeneratorSpi");
         var1.addAlgorithm("KeyGenerator.NTRU", "org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKeyGeneratorSpi");
         NTRUKeyFactorySpi var2 = new NTRUKeyFactorySpi();
         var1.addAlgorithm("Cipher.NTRU", "org.bouncycastle.pqc.jcajce.provider.ntru.NTRUCipherSpi$Base");
         var1.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_ntru, "NTRU");
         this.registerOid(var1, BCObjectIdentifiers.ntruhps2048509, "NTRU", var2);
         this.registerOid(var1, BCObjectIdentifiers.ntruhps2048677, "NTRU", var2);
         this.registerOid(var1, BCObjectIdentifiers.ntruhps4096821, "NTRU", var2);
         this.registerOid(var1, BCObjectIdentifiers.ntruhps40961229, "NTRU", var2);
         this.registerOid(var1, BCObjectIdentifiers.ntruhrss701, "NTRU", var2);
         this.registerOid(var1, BCObjectIdentifiers.ntruhrss1373, "NTRU", var2);
         var1.addAlgorithm("Kem.NTRU", "org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKEMSpi");
         var1.addAlgorithm("Alg.Alias.Kem." + BCObjectIdentifiers.pqc_kem_ntru, "NTRU");
      }
   }
}
