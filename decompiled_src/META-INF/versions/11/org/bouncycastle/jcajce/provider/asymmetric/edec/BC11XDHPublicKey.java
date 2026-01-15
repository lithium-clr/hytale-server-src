package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;

class BC11XDHPublicKey extends BCXDHPublicKey implements XECPublicKey {
   BC11XDHPublicKey(AsymmetricKeyParameter var1) {
      super(var1);
   }

   BC11XDHPublicKey(SubjectPublicKeyInfo var1) {
      super(var1);
   }

   BC11XDHPublicKey(byte[] var1, byte[] var2) throws InvalidKeySpecException {
      super(var1, var2);
   }

   @Override
   public AlgorithmParameterSpec getParams() {
      return this.xdhPublicKey instanceof X448PublicKeyParameters ? NamedParameterSpec.X448 : NamedParameterSpec.X25519;
   }
}
