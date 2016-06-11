(ns sts.cryptfns)

;; Selected safe modulus p and generator g from RFC http://tools.ietf.org/html/rfc3526
(def p 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF) ; modulus

(def g 2N) ; generator

(defn bi->ba
  "bigint to bytearray"
  [bi]
  (.toByteArray (biginteger bi))) 

(defn rand-bytes
  "Generate [size] bytes of Cryptographically random data"
  [size]
  (let [rand (java.security.SecureRandom/getInstance "SHA1PRNG")
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

;; Sign - Nakkaya
(defn generate-keys
  "Generate a public/private RSA java.security.Keypair"
  []
  (let [generator (doto (java.security.KeyPairGenerator/getInstance "RSA")
                    (.initialize 1024))]
    (.generateKeyPair generator)))

(defn sign
  "RSA sign data (bytes) with private-key (sun.security.rsa.RSAPrivateCrtKeyImpl)"
  [data private-key]
  (let [sig (doto (java.security.Signature/getInstance "SHA256withRSA")
              (.initSign private-key (java.security.SecureRandom.))
              (.update data))]
    (.sign sig)))

(defn verify
  "Verify RSA signature (bytes) on data (bytes) using public-key"
  [signature data public-key]
  (let [sig (doto (java.security.Signature/getInstance "SHA256withRSA")
              (.initVerify public-key)
              (.update data))]
    (.verify sig signature)))

;; HMAC - Nakkaya from HOTP
(defn hmac
  "Apply HMAC to bytearr (byte-array) using secret (byte-array) as the key"
  [secret bytearr]
  (let [key-spec (javax.crypto.spec.SecretKeySpec. secret "HmacSHA256")
        mac (doto (javax.crypto.Mac/getInstance "HmacSHA256")
              (.init key-spec))
        hash (->> (.doFinal mac bytearr)
                  (into []))]
    hash))

