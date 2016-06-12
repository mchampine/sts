(ns sts.sts-mac
  (:require [sts.cryptfns :refer :all]
            [sts.util :refer :all]))

;; https://en.wikipedia.org/wiki/Station-to-Station_protocol#STS-MAC
;; E=encrypt, S=sign, k=shared key, b=bob's private key
;; (0) Alice and Bob exchange public keys, and agree on parameters p and g
;; (1) Alice → Bob : g^x
;; (2) Alice ← Bob : g^y, Sb(g^y, g^x), MACk(Sb(g^y, g^x)))
;; (3) Alice Verifies (2)
;; (4) Alice → Bob : Sa(g^x, g^y), MACk(Sa(g^x, g^y))
;; (5) Bob Verifies (4)

;; (0) Alice and Bob exchange public keys, and agree on parameters p and g
;; (0) see cryptfns for parameters p and g
(def alices-keys (generate-keys))
(def alices-pubkey (.getPublic alices-keys))    ; share with Bob
(def alices-privkey (.getPrivate alices-keys))
(def bobs-keys (generate-keys))
(def bobs-pubkey (.getPublic bobs-keys))        ; share with Alice
(def bobs-privkey (.getPrivate bobs-keys))

;; (1) Alice → Bob : g^x
(def alice-x (BigInteger. (rand-bytes (/ 2048 8))))
(def alice-g-to-the-x  (powermod g alice-x p))      ; share g^x with Bob

;; (2) Alice ← Bob : g^y, Sb(g^y, g^x) MACk(SB(g^y, g^x))
(def bob-y (BigInteger. (rand-bytes (/ 2048 8))))
(def bob-g-to-the-y  (powermod g bob-y p))          ; g^y
(def gygx (concat (bi->ba bob-g-to-the-y) (bi->ba alice-g-to-the-x)))
(def bobs-signature (sign (byte-array gygx) bobs-privkey))
(def bob-K (powermod alice-g-to-the-x bob-y p))
(def bobs-hmac-sig (hmac (bi->ba bob-K) bobs-signature))

;; serialized message for bob to send to alice
(def bob-to-alice-step2  {:gy bob-g-to-the-y :sb (base64 bobs-signature)
   :mac (base64 (byte-array bobs-hmac-sig))})

;; (3) Alice Verifies (2)
(def alice-K (powermod bob-g-to-the-y alice-x p))        ; compute shared key
(= bobs-hmac-sig (hmac (bi->ba alice-K) bobs-signature)) ; Check the HMAC
(verify bobs-signature (byte-array gygx) bobs-pubkey)    ; check the sig

;; (4) Alice → Bob : Sa(g^x, g^y), MACk(Sa(g^x, g^y))
(def gxgy (concat (bi->ba alice-g-to-the-x) (bi->ba bob-g-to-the-y)))
(def alices-signature (sign (byte-array gxgy) alices-privkey))
(def alices-hmac-sig (hmac (bi->ba alice-K) alices-signature))

;; serialized message for alice to send to bob
(def alice-to-bob-step4  {:sa (base64 alices-signature)
   :mac (base64 (byte-array alices-hmac-sig))})

;; (5) Bob Verifies (4)
(= alices-hmac-sig (hmac (bi->ba bob-K) alices-signature)) ; Check the HMAC
(verify alices-signature (byte-array gxgy) alices-pubkey)  ; check the sig

;; At this point Alice and Bob have a verified shared symmetric key
(= alice-K bob-K)  ; sanity check
