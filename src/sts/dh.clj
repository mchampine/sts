(ns sts.dh
  (:require [sts.cryptfns :refer :all]))

;; Ordinary Diffie-Hellman

;; Alice sends g^x to Bob
(def alice-x (BigInteger. (rand-bytes (/ 2048 8))))
(def alice-g-to-the-x  (powermod g alice-x p))

;; Bob sends g^y to Alice
(def bob-y (BigInteger. (rand-bytes (/ 2048 8))))
(def bob-g-to-the-y  (powermod g bob-y p))

;; Bob's key is (g^x)^y
(def bob-shared-secret (powermod alice-g-to-the-x bob-y p))

;; Alice's key is (g^y)^x
(def alice-shared-secret (powermod bob-g-to-the-y alice-x p))

;; They are equal, and therefore have established a shared secret
(= alice-shared-secret bob-shared-secret)  ;; true
