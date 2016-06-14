(ns sts.dh
  (:require [sts.cryptfns :refer :all]
            [sts.util :refer :all]
            [clojure.core.async :refer [go put! take! chan close! <! >!]]))

;; Basic Diffie-Hellman

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


;; Basic Diffie-Hellman sequenced with a core.async handshake

(defn pr-md5
  "Print md5 fingerprint of big integer (k)ey for (p)erson, for easy key comparison"
  [p k]
  (println "md5 of" (str p "'s key:") (md5 (bi->ba k))))

(let [alice-to-bob-chan (chan)
      bob-to-alice-chan (chan)]

  ;; Alice's side of the handshake
  (let [alice-x (BigInteger. (rand-bytes (/ 2048 8)))
        alice-g-to-the-x (powermod g alice-x p)]
    (go (>! alice-to-bob-chan alice-g-to-the-x))
    (go (let [bobgy (<! bob-to-alice-chan)]
          (pr-md5 "alice" (powermod bobgy alice-x p)))))

  ;; Bob's side of the handshake
  (let [bob-y (BigInteger. (rand-bytes (/ 2048 8)))
        bob-g-to-the-y (powermod g bob-y p)]
    (go (let [alicegx (<! alice-to-bob-chan)]
          (pr-md5 "  bob" (powermod alicegx bob-y p))))
    (go (>! bob-to-alice-chan bob-g-to-the-y))))


;; Basic Diffie-Hellman sequence with a core.async handshake
;; Using put! and take! instead of >! <!

;; Set up channels
(def alice-to-bob-chan (chan))
(def bob-to-alice-chan (chan))

;; Alice
(let [alice-x (BigInteger. (rand-bytes (/ 2048 8)))
      alice-g-to-the-x (powermod g alice-x p)]
  (put! alice-to-bob-chan alice-g-to-the-x)
  (take! bob-to-alice-chan
         (fn [bobgy] (pr-md5 "alice" (powermod bobgy alice-x p)))))

;; Bob
(let [bob-y (BigInteger. (rand-bytes (/ 2048 8)))
      bob-g-to-the-y (powermod g bob-y p)]
  (take! alice-to-bob-chan
         (fn [alicegx] (pr-md5 "  bob" (powermod alicegx bob-y p))))
  (put! bob-to-alice-chan bob-g-to-the-y))
