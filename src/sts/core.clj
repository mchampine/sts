(ns sts.core
  (:require [sts.cryptfns :refer :all]))

;; http://en.wikipedia.org/wiki/Station-to-Station_protocol
;; E=encrypt, S=sign, k=shared key, b=bob's private key
;; (1) Alice → Bob : g^x
;; (2) Alice ← Bob : g^y, Ek(Sb(g^y, g^x))
;; (3) Alice → Bob : Ek(Sa(g^x, g^y))

;; STS-MAC variant

;; (1) Alice → Bob : g^x
(def alice-x (BigInteger. (rand-bytes (/ 2048 8))))
(def alice-g-to-the-x  (powermod g alice-x p))
;; Alice sends alice-g-to-the-x to bob

;; (2) Alice ← Bob : g^y, Sb(g^y, g^x) MACk(SB(g^y, g^x))
(def bob-y (BigInteger. (rand-bytes (/ 2048 8))))
(def bob-g-to-the-y  (powermod g bob-y p))

(def gygx (concat (bi->ba bob-g-to-the-y) (bi->ba alice-g-to-the-x)))

(def bobs-keys (generate-keys))  ;; note - to be provided out of band
(def bobs-signature (sign (byte-array gygx) (.getPrivate bobs-keys)))
;; (.getPublic bobs-keys)
;; (.getPrivateExponent (.getPrivate bobs-keys))
;; (map int bobs-signature)

(def bob-K (powermod alice-g-to-the-x bob-y p))
(def bobs-hmac-sig (hmac (bi->ba bob-K) bobs-signature))

;; (2) Bob sends bob-g-to-the-y, bobs-signature, and bobs-hmac-sig to Alice

;; (3) Alice → Bob : SA(g^x, g^y), EK(SA(g^x, g^y))
(def gxgy (concat (bi->ba alice-g-to-the-x) (bi->ba bob-g-to-the-y)))

(def alices-keys (generate-keys))
(def alices-signature (sign (byte-array gxgy) (.getPrivate alices-keys)))

(def alice-K (powermod bob-g-to-the-y alice-x p))
(def alices-hmac-sig (hmac (bi->ba alice-K) alices-signature))

(= alice-K bob-K)  ; true if the math is correct (sanity check)

;; (3) Alice sends alices-signature and alices-hmac-sig to Bob


;;; (4) Validation

;; (4a) Alice Validates what she gets from Bob
(= bobs-hmac-sig (hmac (bi->ba alice-K) bobs-signature)) ; Check the HMAC
(verify bobs-signature (byte-array gygx) (.getPublic bobs-keys)) ;; check the sig

;; (4b) Bob Validates what he gets from Alice
(= alices-hmac-sig (hmac (bi->ba bob-K) alices-signature)) ; Check the HMAC
(verify alices-signature (byte-array gxgy) (.getPublic alices-keys)) ;; check the sig

;; At this point Alice and Bob have a verified shared symmetric key
;; alice-K is the same as bob-K
;; 

;; Note: Should use Galois/Counter Mode for Autheenticated AES128 Encryption.
;; Available in Java 8 (javax.crypto.Cipher/getInstance "AES/GCM/NoPadding")
;; or in BouncyCastle
