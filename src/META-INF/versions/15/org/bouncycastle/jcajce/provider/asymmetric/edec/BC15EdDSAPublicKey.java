package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.math.BigInteger;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.util.Arrays;

class BC15EdDSAPublicKey extends BCEdDSAPublicKey implements EdECPublicKey {
   BC15EdDSAPublicKey(AsymmetricKeyParameter var1) {
      super(var1);
   }

   BC15EdDSAPublicKey(SubjectPublicKeyInfo var1) {
      super(var1);
   }

   BC15EdDSAPublicKey(byte[] var1, byte[] var2) throws InvalidKeySpecException {
      super(var1, var2);
   }

   @Override
   public EdECPoint getPoint() {
      byte[] var1 = this.getPointEncoding();
      Arrays.reverseInPlace(var1);
      boolean var2 = (var1[0] & 128) != 0;
      var1[0] = (byte)(var1[0] & 127);
      return new EdECPoint(var2, new BigInteger(1, var1));
   }

   @Override
   public NamedParameterSpec getParams() {
      return this.eddsaPublicKey instanceof Ed448PublicKeyParameters ? NamedParameterSpec.ED448 : NamedParameterSpec.ED25519;
   }
}
