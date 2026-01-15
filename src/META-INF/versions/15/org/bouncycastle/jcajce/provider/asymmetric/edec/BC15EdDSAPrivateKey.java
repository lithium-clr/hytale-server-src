package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;

class BC15EdDSAPrivateKey extends BCEdDSAPrivateKey implements EdECPrivateKey {
   BC15EdDSAPrivateKey(AsymmetricKeyParameter var1) {
      super(var1);
   }

   BC15EdDSAPrivateKey(PrivateKeyInfo var1) throws IOException {
      super(var1);
   }

   @Override
   public Optional<byte[]> getBytes() {
      return this.eddsaPrivateKey instanceof Ed448PrivateKeyParameters
         ? Optional.of(((Ed448PrivateKeyParameters)this.eddsaPrivateKey).getEncoded())
         : Optional.of(((Ed25519PrivateKeyParameters)this.eddsaPrivateKey).getEncoded());
   }

   @Override
   public NamedParameterSpec getParams() {
      return this.eddsaPrivateKey instanceof Ed448PrivateKeyParameters ? NamedParameterSpec.ED448 : NamedParameterSpec.ED25519;
   }

   @Override
   public EdDSAPublicKey getPublicKey() {
      return this.eddsaPrivateKey instanceof Ed448PrivateKeyParameters
         ? new BC15EdDSAPublicKey(((Ed448PrivateKeyParameters)this.eddsaPrivateKey).generatePublicKey())
         : new BC15EdDSAPublicKey(((Ed25519PrivateKeyParameters)this.eddsaPrivateKey).generatePublicKey());
   }
}
