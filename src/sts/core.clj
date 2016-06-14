(ns sts.core
  (:require [sts.cryptfns :refer :all]
            [sts.util :refer :all]
            [clojure.core.async :refer [put! take! chan close!]]))

;; http://en.wikipedia.org/wiki/Station-to-Station_protocol
;; E=encrypt, S=sign, k=shared key, b=bob's private key
;; (0) Alice and Bob exchange public keys, and agree on parameters p and g
;; (1) Alice → Bob : g^x
;; (2) Alice ← Bob : g^y, Ek(Sb(g^y, g^x))
;; (3) Alice Verifies (2)
;; (4) Alice → Bob : Ek(Sa(g^x, g^y))
;; (5) Bob Verifies (4)

;; (0) Alice and Bob exchange public keys, and agree on parameters p and g
;; (0) See cryptfns for parameters p and g
(def alices-keys (generate-keys))
(def alices-pubkey (.getPublic alices-keys))  ; share with Bob out of band
(def alices-privkey (.getPrivate alices-keys))
(def bobs-keys (generate-keys))
(def bobs-pubkey (.getPublic bobs-keys))      ; share with Alice out of band
(def bobs-privkey (.getPrivate bobs-keys))

;; TODO use core.async queues to create a handshake between alice and bob


;; (1) Alice → Bob : g^x
(def alice-x (BigInteger. (rand-bytes (/ 2048 8))))
(def alice-g-to-the-x  (powermod g alice-x p))      ; send g^x to Bob

;; (2) Alice ← Bob : g^y, Ek(Sb(g^y, g^x))
(def bob-y (BigInteger. (rand-bytes (/ 2048 8))))
(def bob-g-to-the-y  (powermod g bob-y p))          ; g^y
(def gygx (concat (bi->ba bob-g-to-the-y) (bi->ba alice-g-to-the-x)))
(def bobs-signature (sign (byte-array gygx) bobs-privkey))
(def bob-K (powermod alice-g-to-the-x bob-y p))
(def bobs-encrypted-sig (encrypt bobs-signature (bi->ba bob-K) "STS Rocks"))

;; serialized message for bob to send to alice
(def bob-to-alice-step2  {:gy bob-g-to-the-y :sb bobs-encrypted-sig})

;; (3) Alice Verifies (2)
(def alice-K (powermod bob-g-to-the-y alice-x p)) ; compute shared key
(def bobs-decrypted-sig (decrypt bobs-encrypted-sig (bi->ba alice-K) "STS Rocks"))
(verify bobs-decrypted-sig (byte-array gygx) bobs-pubkey) ; check the sig

;; (4) Alice → Bob : Ek(SA(g^x, g^y))
(def gxgy (concat (bi->ba alice-g-to-the-x) (bi->ba bob-g-to-the-y)))
(def alices-signature (sign (byte-array gxgy) alices-privkey))
(def alices-encrypted-sig (encrypt alices-signature (bi->ba alice-K) "STS Rocks"))

;; alice sends alices-encrypted-sig to bob

;; (5) Bob Verifies (4)
(def alices-decrypted-sig (decrypt alices-encrypted-sig (bi->ba bob-K) "STS Rocks"))
(verify alices-decrypted-sig (byte-array gxgy) alices-pubkey) ; check the sig

;; At this point Alice and Bob have a verified shared symmetric key
(= alice-K bob-K)  ; sanity check


;; TODO use core.async queues to create a handshake between alice and bob
;; TODO convert from using dummy arguments to passing all needed values.

;; Set up Channels
(def alice-to-bob-chan (chan))
(def bob-to-alice-chan (chan))

;; Alice Side
(put! alice-to-bob-chan "alice g^x")
(take! bob-to-alice-chan (fn [x] (println "alice expects bob g^y, etc and gets:" x)))
(put! alice-to-bob-chan "alice Ek(Sa(gxgy))")
(put! alice-to-bob-chan "alice is done")
(take! bob-to-alice-chan (fn [x] (println "alice expects bob is done and gets:" x)))

;; Bob Side
(take! alice-to-bob-chan (fn [x] (println "bob expects alice g^x and gets:" x)))
(put! bob-to-alice-chan "bob g^y, etc")
(take! alice-to-bob-chan (fn [x] (println "bob expects alice Ek(Sa(gxgy)) and gets:" x)))
(take! alice-to-bob-chan (fn [x] (println "bob expects alice is done and gets:" x)))
(put! bob-to-alice-chan "bob is done.")
