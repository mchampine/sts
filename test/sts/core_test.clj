(ns sts.core-test
  (:require [clojure.test :refer :all]
            [sts.util :refer :all]
            [sts.cryptfns :refer :all]))

(deftest encrypt-decrypt
  (let [msg (.getBytes "Sqeamish Ossifrage")
        k (bi->ba (BigInteger. (rand-bytes (/ 2048 8))))
        ct (encrypt msg k "Addl Auth")]
    (is (= (String. msg) (String. (decrypt ct k "Addl Auth"))))))

(deftest sign-verify
  (let [keys (generate-keys)
        pubkey (.getPublic keys)
        privkey (.getPrivate keys)
        msg (.getBytes "Sqeamish Ossifrage")
        k (bi->ba (BigInteger. (rand-bytes (/ 2048 8))))
        ksig (sign k privkey)
        msgsig (sign msg privkey)]
    (is (verify ksig k pubkey))
    (is (verify msgsig msg pubkey))))

(deftest hmac-test
  (let [msg (.getBytes "Sqeamish Ossifrage")
        k (byte-array [-28 6 -60 -14])
        kmac (hmac k msg)
        b64mac (base64 (byte-array kmac))]
    (is (= b64mac "TZ0oMg2q2jQbCru8TIEc0APhNKIZhk7PVnZm+lBYv+g="))))


