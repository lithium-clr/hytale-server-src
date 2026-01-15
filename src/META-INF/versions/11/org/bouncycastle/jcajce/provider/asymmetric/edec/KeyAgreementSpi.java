package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.agreement.XDHUnifiedAgreement;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.params.XDHUPrivateParameters;
import org.bouncycastle.crypto.params.XDHUPublicParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class KeyAgreementSpi extends BaseAgreementSpi {
   private RawAgreement agreement;
   private DHUParameterSpec dhuSpec;
   private byte[] result;

   KeyAgreementSpi(String var1) {
      super(var1, null);
   }

   KeyAgreementSpi(String var1, DerivationFunction var2) {
      super(var1, var2);
   }

   @Override
   protected byte[] doCalcSecret() {
      return this.result;
   }

   @Override
   protected void doInitFromKey(Key var1, AlgorithmParameterSpec var2, SecureRandom var3) throws InvalidKeyException, InvalidAlgorithmParameterException {
      AsymmetricKeyParameter var4 = getLwXDHKeyPrivate(var1);
      if (var4 instanceof X25519PrivateKeyParameters) {
         this.agreement = this.getAgreement("X25519");
      } else {
         if (!(var4 instanceof X448PrivateKeyParameters)) {
            throw new InvalidKeyException("unsupported private key type");
         }

         this.agreement = this.getAgreement("X448");
      }

      this.ukmParameters = null;
      if (var2 instanceof DHUParameterSpec) {
         if (this.kaAlgorithm.indexOf(85) < 0) {
            throw new InvalidAlgorithmParameterException("agreement algorithm not DHU based");
         }

         this.dhuSpec = (DHUParameterSpec)var2;
         this.ukmParameters = this.dhuSpec.getUserKeyingMaterial();
         this.agreement
            .init(
               new XDHUPrivateParameters(
                  var4,
                  ((BCXDHPrivateKey)this.dhuSpec.getEphemeralPrivateKey()).engineGetKeyParameters(),
                  ((BCXDHPublicKey)this.dhuSpec.getEphemeralPublicKey()).engineGetKeyParameters()
               )
            );
      } else if (var2 != null) {
         this.agreement.init(var4);
         if (!(var2 instanceof UserKeyingMaterialSpec)) {
            throw new InvalidAlgorithmParameterException("unknown ParameterSpec");
         }

         if (this.kdf == null) {
            throw new InvalidAlgorithmParameterException("no KDF specified for UserKeyingMaterialSpec");
         }

         this.ukmParameters = ((UserKeyingMaterialSpec)var2).getUserKeyingMaterial();
      } else {
         this.agreement.init(var4);
      }

      if (this.kdf != null && this.ukmParameters == null) {
         this.ukmParameters = new byte[0];
      }
   }

   @Override
   protected Key engineDoPhase(Key var1, boolean var2) throws InvalidKeyException, IllegalStateException {
      if (this.agreement == null) {
         throw new IllegalStateException(this.kaAlgorithm + " not initialised.");
      } else if (!var2) {
         throw new IllegalStateException(this.kaAlgorithm + " can only be between two parties.");
      } else {
         AsymmetricKeyParameter var3 = this.getLwXDHKeyPublic(var1);
         this.result = new byte[this.agreement.getAgreementSize()];
         if (this.dhuSpec != null) {
            this.agreement
               .calculateAgreement(
                  new XDHUPublicParameters(var3, ((BCXDHPublicKey)this.dhuSpec.getOtherPartyEphemeralKey()).engineGetKeyParameters()), this.result, 0
               );
         } else {
            this.agreement.calculateAgreement(var3, this.result, 0);
         }

         return null;
      }
   }

   private RawAgreement getAgreement(String var1) throws InvalidKeyException {
      if (!this.kaAlgorithm.equals("XDH") && !this.kaAlgorithm.startsWith(var1)) {
         throw new InvalidKeyException("inappropriate key for " + this.kaAlgorithm);
      } else if (this.kaAlgorithm.indexOf(85) > 0) {
         return var1.startsWith("X448") ? new XDHUnifiedAgreement(new X448Agreement()) : new XDHUnifiedAgreement(new X25519Agreement());
      } else {
         return (RawAgreement)(var1.startsWith("X448") ? new X448Agreement() : new X25519Agreement());
      }
   }

   private static AsymmetricKeyParameter getLwXDHKeyPrivate(Key var0) throws InvalidKeyException {
      if (var0 instanceof BCXDHPrivateKey) {
         return ((BCXDHPrivateKey)var0).engineGetKeyParameters();
      } else if (var0 instanceof XECPrivateKey) {
         XECPrivateKey var1 = (XECPrivateKey)var0;
         Optional var2 = var1.getScalar();
         if (!var2.isPresent()) {
            throw new InvalidKeyException("cannot use XEC private key without scalar");
         } else {
            String var3 = var1.getAlgorithm();
            if ("X25519".equalsIgnoreCase(var3)) {
               return getX25519PrivateKey((byte[])var2.get());
            } else if ("X448".equalsIgnoreCase(var3)) {
               return getX448PrivateKey((byte[])var2.get());
            } else {
               if ("XDH".equalsIgnoreCase(var3)) {
                  AlgorithmParameterSpec var4 = var1.getParams();
                  if (var4 instanceof NamedParameterSpec) {
                     NamedParameterSpec var5 = (NamedParameterSpec)var4;
                     String var6 = var5.getName();
                     if ("X25519".equalsIgnoreCase(var6)) {
                        return getX25519PrivateKey((byte[])var2.get());
                     }

                     if ("X448".equalsIgnoreCase(var6)) {
                        return getX448PrivateKey((byte[])var2.get());
                     }
                  }
               }

               throw new InvalidKeyException("cannot use XEC private key with unknown algorithm");
            }
         }
      } else {
         throw new InvalidKeyException("cannot identify XDH private key");
      }
   }

   private AsymmetricKeyParameter getLwXDHKeyPublic(Key var1) throws InvalidKeyException {
      if (var1 instanceof BCXDHPublicKey) {
         return ((BCXDHPublicKey)var1).engineGetKeyParameters();
      } else if (var1 instanceof XECPublicKey) {
         XECPublicKey var2 = (XECPublicKey)var1;
         BigInteger var3 = var2.getU();
         if (var3.signum() < 0) {
            throw new InvalidKeyException("cannot use XEC public key with negative U value");
         } else {
            String var4 = var2.getAlgorithm();
            if ("X25519".equalsIgnoreCase(var4)) {
               return getX25519PublicKey(var3);
            } else if ("X448".equalsIgnoreCase(var4)) {
               return getX448PublicKey(var3);
            } else {
               if ("XDH".equalsIgnoreCase(var4)) {
                  AlgorithmParameterSpec var5 = var2.getParams();
                  if (var5 instanceof NamedParameterSpec) {
                     NamedParameterSpec var6 = (NamedParameterSpec)var5;
                     String var7 = var6.getName();
                     if ("X25519".equalsIgnoreCase(var7)) {
                        return getX25519PublicKey(var3);
                     }

                     if ("X448".equalsIgnoreCase(var7)) {
                        return getX448PublicKey(var3);
                     }
                  }
               }

               throw new InvalidKeyException("cannot use XEC public key with unknown algorithm");
            }
         }
      } else {
         throw new InvalidKeyException("cannot identify XDH public key");
      }
   }

   private static byte[] getPublicKeyData(int var0, BigInteger var1) throws InvalidKeyException {
      try {
         return Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(var0, var1));
      } catch (RuntimeException var3) {
         throw new InvalidKeyException("cannot use XEC public key with invalid U value");
      }
   }

   private static X25519PrivateKeyParameters getX25519PrivateKey(byte[] var0) throws InvalidKeyException {
      if (32 != var0.length) {
         throw new InvalidKeyException("cannot use XEC private key (X25519) with scalar of incorrect length");
      } else {
         return new X25519PrivateKeyParameters(var0, 0);
      }
   }

   private static X25519PublicKeyParameters getX25519PublicKey(BigInteger var0) throws InvalidKeyException {
      byte[] var1 = getPublicKeyData(32, var0);
      return new X25519PublicKeyParameters(var1, 0);
   }

   private static X448PrivateKeyParameters getX448PrivateKey(byte[] var0) throws InvalidKeyException {
      if (56 != var0.length) {
         throw new InvalidKeyException("cannot use XEC private key (X448) with scalar of incorrect length");
      } else {
         return new X448PrivateKeyParameters(var0, 0);
      }
   }

   private static X448PublicKeyParameters getX448PublicKey(BigInteger var0) throws InvalidKeyException {
      byte[] var1 = getPublicKeyData(56, var0);
      return new X448PublicKeyParameters(var1, 0);
   }

   public static final class X25519 extends KeyAgreementSpi {
      public X25519() {
         super("X25519");
      }
   }

   public static class X25519UwithSHA256CKDF extends KeyAgreementSpi {
      public X25519UwithSHA256CKDF() {
         super("X25519UwithSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
      }
   }

   public static class X25519UwithSHA256KDF extends KeyAgreementSpi {
      public X25519UwithSHA256KDF() {
         super("X25519UwithSHA256KDF", new KDF2BytesGenerator(DigestFactory.createSHA256()));
      }
   }

   public static final class X25519withSHA256CKDF extends KeyAgreementSpi {
      public X25519withSHA256CKDF() {
         super("X25519withSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
      }
   }

   public static final class X25519withSHA256HKDF extends KeyAgreementSpi {
      public X25519withSHA256HKDF() {
         super("X25519withSHA256HKDF", new HKDFBytesGenerator(DigestFactory.createSHA256()));
      }
   }

   public static final class X25519withSHA256KDF extends KeyAgreementSpi {
      public X25519withSHA256KDF() {
         super("X25519withSHA256KDF", new KDF2BytesGenerator(DigestFactory.createSHA256()));
      }
   }

   public static class X25519withSHA384CKDF extends KeyAgreementSpi {
      public X25519withSHA384CKDF() {
         super("X25519withSHA384CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
      }
   }

   public static class X25519withSHA512CKDF extends KeyAgreementSpi {
      public X25519withSHA512CKDF() {
         super("X25519withSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
      }
   }

   public static final class X448 extends KeyAgreementSpi {
      public X448() {
         super("X448");
      }
   }

   public static class X448UwithSHA512CKDF extends KeyAgreementSpi {
      public X448UwithSHA512CKDF() {
         super("X448UwithSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
      }
   }

   public static class X448UwithSHA512KDF extends KeyAgreementSpi {
      public X448UwithSHA512KDF() {
         super("X448UwithSHA512KDF", new KDF2BytesGenerator(DigestFactory.createSHA512()));
      }
   }

   public static final class X448withSHA256CKDF extends KeyAgreementSpi {
      public X448withSHA256CKDF() {
         super("X448withSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
      }
   }

   public static class X448withSHA384CKDF extends KeyAgreementSpi {
      public X448withSHA384CKDF() {
         super("X448withSHA384CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
      }
   }

   public static final class X448withSHA512CKDF extends KeyAgreementSpi {
      public X448withSHA512CKDF() {
         super("X448withSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
      }
   }

   public static final class X448withSHA512HKDF extends KeyAgreementSpi {
      public X448withSHA512HKDF() {
         super("X448withSHA512HKDF", new HKDFBytesGenerator(DigestFactory.createSHA512()));
      }
   }

   public static final class X448withSHA512KDF extends KeyAgreementSpi {
      public X448withSHA512KDF() {
         super("X448withSHA512KDF", new KDF2BytesGenerator(DigestFactory.createSHA512()));
      }
   }

   public static final class XDH extends KeyAgreementSpi {
      public XDH() {
         super("XDH");
      }
   }
}
