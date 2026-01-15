package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class SignatureSpi extends java.security.SignatureSpi {
   private static final byte[] EMPTY_CONTEXT = new byte[0];
   private final String algorithm;
   private Signer signer;

   SignatureSpi(String var1) {
      this.algorithm = var1;
   }

   @Override
   protected void engineInitVerify(PublicKey var1) throws InvalidKeyException {
      AsymmetricKeyParameter var2 = getLwEdDSAKeyPublic(var1);
      if (var2 instanceof Ed25519PublicKeyParameters) {
         this.signer = this.getSigner("Ed25519");
      } else {
         if (!(var2 instanceof Ed448PublicKeyParameters)) {
            throw new InvalidKeyException("unsupported public key type");
         }

         this.signer = this.getSigner("Ed448");
      }

      this.signer.init(false, var2);
   }

   @Override
   protected void engineInitSign(PrivateKey var1) throws InvalidKeyException {
      AsymmetricKeyParameter var2 = getLwEdDSAKeyPrivate(var1);
      if (var2 instanceof Ed25519PrivateKeyParameters) {
         this.signer = this.getSigner("Ed25519");
      } else {
         if (!(var2 instanceof Ed448PrivateKeyParameters)) {
            throw new InvalidKeyException("unsupported private key type");
         }

         this.signer = this.getSigner("Ed448");
      }

      this.signer.init(true, var2);
   }

   static Ed25519PrivateKeyParameters getEd25519PrivateKey(byte[] var0) throws InvalidKeyException {
      if (32 != var0.length) {
         throw new InvalidKeyException("cannot use EdEC private key (Ed25519) with bytes of incorrect length");
      } else {
         return new Ed25519PrivateKeyParameters(var0, 0);
      }
   }

   static Ed25519PublicKeyParameters getEd25519PublicKey(EdECPoint var0) throws InvalidKeyException {
      byte[] var1 = getPublicKeyData(32, var0);
      return new Ed25519PublicKeyParameters(var1, 0);
   }

   static Ed448PrivateKeyParameters getEd448PrivateKey(byte[] var0) throws InvalidKeyException {
      if (57 != var0.length) {
         throw new InvalidKeyException("cannot use EdEC private key (Ed448) with bytes of incorrect length");
      } else {
         return new Ed448PrivateKeyParameters(var0, 0);
      }
   }

   static Ed448PublicKeyParameters getEd448PublicKey(EdECPoint var0) throws InvalidKeyException {
      byte[] var1 = getPublicKeyData(57, var0);
      return new Ed448PublicKeyParameters(var1, 0);
   }

   private static AsymmetricKeyParameter getLwEdDSAKeyPrivate(Key var0) throws InvalidKeyException {
      if (var0 instanceof BCEdDSAPrivateKey) {
         return ((BCEdDSAPrivateKey)var0).engineGetKeyParameters();
      } else if (var0 instanceof EdECPrivateKey) {
         EdECPrivateKey var1 = (EdECPrivateKey)var0;
         Optional var2 = var1.getBytes();
         if (!var2.isPresent()) {
            throw new InvalidKeyException("cannot use EdEC private key without bytes");
         } else {
            String var3 = var1.getAlgorithm();
            if ("Ed25519".equalsIgnoreCase(var3)) {
               return getEd25519PrivateKey((byte[])var2.get());
            } else if ("Ed448".equalsIgnoreCase(var3)) {
               return getEd448PrivateKey((byte[])var2.get());
            } else {
               if ("EdDSA".equalsIgnoreCase(var3)) {
                  NamedParameterSpec var4 = var1.getParams();
                  if (var4 instanceof NamedParameterSpec) {
                     NamedParameterSpec var5 = var4;
                     String var6 = var5.getName();
                     if ("Ed25519".equalsIgnoreCase(var6)) {
                        return getEd25519PrivateKey((byte[])var2.get());
                     }

                     if ("Ed448".equalsIgnoreCase(var6)) {
                        return getEd448PrivateKey((byte[])var2.get());
                     }
                  }
               }

               throw new InvalidKeyException("cannot use EdEC private key with unknown algorithm");
            }
         }
      } else {
         throw new InvalidKeyException("cannot identify EdDSA private key");
      }
   }

   private static AsymmetricKeyParameter getLwEdDSAKeyPublic(Key var0) throws InvalidKeyException {
      if (var0 instanceof BCEdDSAPublicKey) {
         return ((BCEdDSAPublicKey)var0).engineGetKeyParameters();
      } else if (var0 instanceof EdECPublicKey) {
         EdECPublicKey var1 = (EdECPublicKey)var0;
         EdECPoint var2 = var1.getPoint();
         String var3 = var1.getAlgorithm();
         if ("Ed25519".equalsIgnoreCase(var3)) {
            return getEd25519PublicKey(var2);
         } else if ("Ed448".equalsIgnoreCase(var3)) {
            return getEd448PublicKey(var2);
         } else {
            if ("EdDSA".equalsIgnoreCase(var3)) {
               NamedParameterSpec var4 = var1.getParams();
               if (var4 instanceof NamedParameterSpec) {
                  NamedParameterSpec var5 = var4;
                  String var6 = var5.getName();
                  if ("Ed25519".equalsIgnoreCase(var6)) {
                     return getEd25519PublicKey(var2);
                  }

                  if ("Ed448".equalsIgnoreCase(var6)) {
                     return getEd448PublicKey(var2);
                  }
               }
            }

            throw new InvalidKeyException("cannot use EdEC public key with unknown algorithm");
         }
      } else {
         throw new InvalidKeyException("cannot identify EdDSA public key");
      }
   }

   private static byte[] getPublicKeyData(int var0, EdECPoint var1) throws InvalidKeyException {
      BigInteger var2 = var1.getY();
      if (var2.signum() < 0) {
         throw new InvalidKeyException("cannot use EdEC public key with negative Y value");
      } else {
         try {
            byte[] var3 = BigIntegers.asUnsignedByteArray(var0, var2);
            if ((var3[0] & 128) == 0) {
               if (var1.isXOdd()) {
                  var3[0] = (byte)(var3[0] | 128);
               }

               return Arrays.reverseInPlace(var3);
            }
         } catch (RuntimeException var4) {
         }

         throw new InvalidKeyException("cannot use EdEC public key with invalid Y value");
      }
   }

   private Signer getSigner(String var1) throws InvalidKeyException {
      if (this.algorithm != null && !var1.equals(this.algorithm)) {
         throw new InvalidKeyException("inappropriate key for " + this.algorithm);
      } else {
         return (Signer)(var1.equals("Ed448") ? new Ed448Signer(EMPTY_CONTEXT) : new Ed25519Signer());
      }
   }

   @Override
   protected void engineUpdate(byte var1) throws SignatureException {
      this.signer.update(var1);
   }

   @Override
   protected void engineUpdate(byte[] var1, int var2, int var3) throws SignatureException {
      this.signer.update(var1, var2, var3);
   }

   @Override
   protected byte[] engineSign() throws SignatureException {
      try {
         return this.signer.generateSignature();
      } catch (CryptoException var2) {
         throw new SignatureException(var2.getMessage());
      }
   }

   @Override
   protected boolean engineVerify(byte[] var1) throws SignatureException {
      return this.signer.verifySignature(var1);
   }

   @Override
   protected void engineSetParameter(String var1, Object var2) throws InvalidParameterException {
      throw new UnsupportedOperationException("engineSetParameter unsupported");
   }

   @Override
   protected Object engineGetParameter(String var1) throws InvalidParameterException {
      throw new UnsupportedOperationException("engineGetParameter unsupported");
   }

   @Override
   protected AlgorithmParameters engineGetParameters() {
      return null;
   }

   public static final class Ed25519 extends SignatureSpi {
      public Ed25519() {
         super("Ed25519");
      }
   }

   public static final class Ed448 extends SignatureSpi {
      public Ed448() {
         super("Ed448");
      }
   }

   public static final class EdDSA extends SignatureSpi {
      public EdDSA() {
         super(null);
      }
   }
}
