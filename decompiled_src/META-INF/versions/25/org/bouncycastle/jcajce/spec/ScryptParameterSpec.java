package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class ScryptParameterSpec extends ScryptKeySpec implements AlgorithmParameterSpec {
   public ScryptParameterSpec(char[] var1, byte[] var2, int var3, int var4, int var5, int var6) {
      super(var1, var2, var3, var4, var5, var6);
   }
}
