(ns sts.dh
  (:require [sts.cryptfns :refer :all]))

;; Ordinary Diffie-Hellman

;; Alice sends g^x to Bob
(def alice-dh-x (BigInteger. (rand-bytes (/ 2048 8))))
(def alice-dh-g-to-the-x  (powermod g alice-dh-x p))

;; Bob sends g^y to Alice
(def bob-dh-y (BigInteger. (rand-bytes (/ 2048 8))))
(def bob-dh-g-to-the-y  (powermod g bob-dh-y p))

;; Bob's key is (g^x)^y
(def bob-dh-shared-secret (powermod alice-dh-g-to-the-x bob-dh-y p))

;; Alice's key is (g^y)^x
(def alice-dh-shared-secret (powermod bob-dh-g-to-the-y alice-dh-x p))

;; They are equal, and therefore have established a shared secret
(= alice-dh-shared-secret bob-dh-shared-secret)  ;; true
