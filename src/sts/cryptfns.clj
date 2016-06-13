(ns sts.cryptfns
  (:require [sts.util :refer :all])
  (:import javax.crypto.KeyGenerator
           javax.crypto.Cipher
           javax.crypto.spec.SecretKeySpec
           javax.crypto.spec.GCMParameterSpec
           java.security.SecureRandom))

;; See https://gist.github.com/praseodym/f2499b3e14d872fe5b4a
;; and http://stackoverflow.com/questions/10221257/is-there-an-aes-library-for-clojure

(def AES_KEY_SIZE 128)    ; bits
(def GCM_NONCE_LENGTH 12) ; bytes
(def GCM_TAG_LENGTH 128)  ; bits

(defn get-raw-key [seed]
  (let [keygen (KeyGenerator/getInstance "AES")
        sr (SecureRandom/getInstance "SHA1PRNG")]
    (.setSeed sr (bytes seed))
    (.init keygen AES_KEY_SIZE sr)
    (.. keygen generateKey getEncoded)))

(defn get-cipher [mode seed spec]
  (let [key-spec (SecretKeySpec. (get-raw-key seed) "AES")
        cipher (Cipher/getInstance "AES/GCM/NoPadding", "SunJCE")]
    (.init cipher mode key-spec spec)
    cipher))

(defn encrypt
  "Encrypt text with key and AAD (additional auth data)
   Return a map {:c ciphertext :n nonce} - base64 values"
  [text key aad]
  (let [bytes (bytes text)
        nonce (rand-bytes GCM_NONCE_LENGTH)
        spec (GCMParameterSpec. GCM_TAG_LENGTH nonce)
        cipher (get-cipher Cipher/ENCRYPT_MODE key spec)]
    (.updateAAD cipher (.getBytes aad))
    {:c (base64 (.doFinal cipher bytes)) :n (base64 nonce)}))

(defn decrypt
  "Decrypt ciphertext :c in encmap using nonce :n
   AAD must match exactly what was passed in or an exception is thrown"
  [encmap key aad]
  (let [spec (GCMParameterSpec. GCM_TAG_LENGTH (debase64 (.getBytes (:n encmap))))
        cipher (get-cipher Cipher/DECRYPT_MODE key spec)]
    (.updateAAD cipher (.getBytes aad))
    (.doFinal cipher (debase64 (.getBytes (:c encmap))))))

;; DH crypto constants

;; Selected safe modulus p and generator g from RFC http://tools.ietf.org/html/rfc3526
(def p 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF) ; modulus

(def g 2N) ; generator

;; Sign - Nakkaya
(defn generate-keys
  "Generate a public/private RSA java.security.Keypair"
  []
  (let [generator (doto (java.security.KeyPairGenerator/getInstance "RSA")
                    (.initialize 2048))]
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

;; HMAC - Nakkaya
(defn hmac
  "Apply HMAC to bytearr (byte-array) using secret (byte-array) as the key"
  [secret bytearr]
  (let [key-spec (javax.crypto.spec.SecretKeySpec. secret "HmacSHA256")
        mac (doto (javax.crypto.Mac/getInstance "HmacSHA256")
              (.init key-spec))
        hash (->> (.doFinal mac bytearr)
                  (into []))]
    hash))
