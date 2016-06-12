(ns sts.util
  (:import org.apache.commons.codec.binary.Base64
           java.security.SecureRandom))

(defn base64 [b]
  (Base64/encodeBase64String b))

(defn debase64 [s]
  (Base64/decodeBase64 (bytes s)))

(defn bi->ba
  "bigint to bytearray"
  [bi]
  (.toByteArray (biginteger bi))) 

(defn rand-bytes
  "Generate [size] bytes of Cryptographically random data"
  [size]
  (let [rand (SecureRandom/getInstance "SHA1PRNG")
        buffer (make-array Byte/TYPE size)]
    (.nextBytes rand buffer) 
    buffer))

(defn powermod
  "Perform modular exponentiation: base, exponent, modulus"
  [b e m]
  (defn m* [p q] (mod (* p q) m))
  (loop [b b, e e, x 1]
    (if (zero? e) x
      (if (even? e) (recur (m* b b) (/ e 2) x)
          (recur (m* b b) (quot e 2) (m* b x))))))
