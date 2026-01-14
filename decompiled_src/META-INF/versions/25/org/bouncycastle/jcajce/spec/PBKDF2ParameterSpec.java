package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2ParameterSpec extends PBEKeySpec implements AlgorithmParameterSpec {
   public PBKDF2ParameterSpec(char[] var1) {
      super(var1);
   }

   public PBKDF2ParameterSpec(char[] var1, byte[] var2, int var3, int var4) {
      super(var1, var2, var3, var4);
   }

   public PBKDF2ParameterSpec(char[] var1, byte[] var2, int var3) {
      super(var1, var2, var3);
   }
}
