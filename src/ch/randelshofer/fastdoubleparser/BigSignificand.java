package ch.randelshofer.fastdoubleparser;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.math.BigInteger;
import java.nio.ByteOrder;

final class BigSignificand {
   private static final long LONG_MASK = 4294967295L;
   private static final VarHandle readIntBE = MethodHandles.byteArrayViewVarHandle(int[].class, ByteOrder.BIG_ENDIAN);
   private final int numInts;
   private final byte[] x;
   private int firstNonZeroInt;

   public BigSignificand(long numBits) {
      if (numBits > 0L && numBits < 2147483647L) {
         int numLongs = (int)(numBits + 63L >>> 6) + 1;
         this.numInts = numLongs << 1;
         int numBytes = numLongs << 3;
         this.x = new byte[numBytes];
         this.firstNonZeroInt = this.numInts;
      } else {
         throw new IllegalArgumentException("numBits=" + numBits);
      }
   }

   public void add(int value) {
      if (value != 0) {
         long carry = value & 4294967295L;

         int i;
         for (i = this.numInts - 1; carry != 0L; i--) {
            long sum = (this.x(i) & 4294967295L) + carry;
            this.x(i, (int)sum);
            carry = sum >>> 32;
         }

         this.firstNonZeroInt = Math.min(this.firstNonZeroInt, i + 1);
      }
   }

   public void fma(int factor, int addend) {
      long factorL = factor & 4294967295L;
      long carry = addend;

      int i;
      for (i = this.numInts - 1; i >= this.firstNonZeroInt; i--) {
         long product = factorL * (this.x(i) & 4294967295L) + carry;
         this.x(i, (int)product);
         carry = product >>> 32;
      }

      if (carry != 0L) {
         this.x(i, (int)carry);
         this.firstNonZeroInt = i;
      }
   }

   public BigInteger toBigInteger() {
      return new BigInteger(this.x);
   }

   private void x(int i, int value) {
      readIntBE.set((byte[])this.x, (int)(i << 2), (int)value);
   }

   private int x(int i) {
      return (int)readIntBE.get((byte[])this.x, (int)(i << 2));
   }
}
