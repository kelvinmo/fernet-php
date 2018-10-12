<?php
/*
 * Fernet-PHP
 *
 * Copyright (C) Kelvin Mo 2014
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

namespace Fernet;

/**
 * An implementation of the Fernet token specification in PHP.
 *
 * @link https://github.com/fernet/spec/blob/master/Spec.md
 */
class Fernet {

    const VERSION = "\x80";

    private $encryption_key;
    private $signing_key;

    /**
     * Creates an instance of the Fernet encoder/decoder
     *
     * @param $key the Fernet key, encoded in base64url format
     */
    public function __construct($key) {
        if (!function_exists('random_bytes') && !function_exists('openssl_random_pseudo_bytes') && !function_exists('mcrypt_create_iv')) {
            throw new \Exception('No backend library found');
        }

        $key = self::base64url_decode($key);

        if (self::safeStrlen($key) !== 32) {
            throw new \Exception('Incorrect key');
        }

        $this->signing_key = self::safeSubstr($key, 0, 16);
        $this->encryption_key = self::safeSubstr($key, 16);
    }

    /**
     * Encodes a Fernet token.
     *
     * @param string $message the message to be encoded in the token
     * @return string the token
     */
    public function encode($message) {
        $iv = $this->getIV();

        // PKCS7 padding
        $pad = 16 - (self::safeStrlen($message) % 16);
        $message .= str_repeat(chr($pad), $pad);

        if (function_exists('openssl_encrypt')) {
            $ciphertext = base64_decode(openssl_encrypt($message, 'aes-128-cbc', $this->encryption_key, OPENSSL_ZERO_PADDING, $iv));
        } elseif (function_exists('mcrypt_encrypt')) {
            $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $this->encryption_key, $message, 'cbc', $iv);
        }

        $signing_base = self::VERSION . pack('NN', 0, $this->getTime()) . $iv . $ciphertext;
        $hash = hash_hmac('sha256', $signing_base, $this->signing_key, true);
        return self::base64url_encode($signing_base . $hash);
    }

    /**
     * Decodes a Fernet token.
     *
     * @param string $token the token to decode
     * @param int $ttl the maximum number of seconds since the creation of the
     * token for the token to be considered valid
     * @return string|null the decoded message, or null if the token is invalid
     * for whatever reason.
     */
    public function decode($token, $ttl = null) {
        $raw = self::base64url_decode($token);

        $hash = self::safeSubstr($raw, -32);
        $signing_base = self::safeSubstr($raw, 0, -32);
        $expected_hash = hash_hmac('sha256', $signing_base, $this->signing_key, true);

        if (!is_string($hash)) {
            return null;
        }
        if (!$this->secureCompare($hash, $expected_hash)) {
            return null;
        }

        $parts = unpack('Cversion/Ndummy/Ntime', self::safeSubstr($signing_base, 0, 9));
        if (chr($parts['version']) != self::VERSION) return null;

        if ($ttl !== null) {
            if ($parts['time'] + $ttl < $this->getTime()) {
                return null;
            }
        }

        $iv = self::safeSubstr($signing_base, 9, 16);
        $ciphertext = self::safeSubstr($signing_base, 25);

        if (function_exists('openssl_decrypt')) {
            $message = openssl_decrypt(base64_encode($ciphertext), 'aes-128-cbc', $this->encryption_key, OPENSSL_ZERO_PADDING, $iv);
        } elseif (function_exists('mcrypt_decrypt')) {
            $message = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $this->encryption_key, $ciphertext, 'cbc', $iv);
        }

        $pad = ord($message[self::safeStrlen($message) - 1]);
        if (substr_count(self::safeSubstr($message, -$pad), chr($pad)) !== $pad) {
            return null;
        }

        return self::safeSubstr($message, 0, -$pad);
    }

    /**
     * Generates an initialisation vector for AES encryption
     *
     * @return string a bytestream containing an initialisation
     * vector
     */
    protected function getIV() {
        if (function_exists('random_bytes')) {
            return random_bytes(16);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            return openssl_random_pseudo_bytes(16);
        } elseif (function_exists('mcrypt_create_iv')) {
            return mcrypt_create_iv(16);
        }
    }

    /**
     * Obtains the current time.
     *
     * @return int the current time
     */
    protected function getTime() {
        return time();
    }

    /**
     * Compares two strings using the same time whether they're equal or not.
     * This function should be used to mitigate timing attacks when, for
     * example, comparing password hashes
     *
     * @param string $str1
     * @param string $str2
     * @return bool true if the two strings are equal
     */
    protected function secureCompare($str1, $str2) {
        if (function_exists('hash_equals')) {
            return hash_equals($str1, $str2);
        }
        $xor = $str1 ^ $str2;
        $result = self::safeStrlen($str1) ^ self::safeStrlen($str2); //not the same length, then fail ($result != 0)
        for ($i = self::safeStrlen($xor) - 1; $i >= 0; --$i) {
            $result += ord($xor[$i]);
        }
        return $result !== 0;
    }

    /**
     * Generates a random key for use in Fernet tokens
     *
     * @return string a base64url encoded key
     */
    static public function generateKey() {
        if (function_exists('random_bytes')) {
            $key = random_bytes(32);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $key = openssl_random_pseudo_bytes(32);
        } elseif (function_exists('mcrypt_create_iv')) {
            $key = mcrypt_create_iv(32);
        } else {
            throw new \Exception('No backend library found');
        }
        return self::base64url_encode($key);
    }
    /**
     * Encodes data encoded with Base 64 Encoding with URL and Filename Safe Alphabet.
     *
     * @param string $data the data to encode
     * @param bool $pad whether padding characters should be included
     * @return string the encoded data
     * @link http://tools.ietf.org/html/rfc4648#section-5
     */
    static public function base64url_encode($data, $pad = true) {
        $encoded = strtr(base64_encode($data), '+/', '-_');
        if (!$pad) $encoded = trim($encoded, '=');
        return $encoded;
    }

    /**
     * Decodes data encoded with Base 64 Encoding with URL and Filename Safe Alphabet.
     *
     * @param string $data the encoded data
     * @return string|bool the original data or FALSE on failure. The returned data may be binary.
     * @link http://tools.ietf.org/html/rfc4648#section-5
     */
    static public function base64url_decode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
    }
    
    /**
     * Safe string length
     *
     * @staticvar boolean $exists
     * @param string $str
     * @return int
     */
    static public function safeStrlen($str)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = function_exists('mb_strlen');
        }
        if ($exists) {
            return mb_strlen($str, '8bit');
        }
        return strlen($str);
    }
    
    /**
     * Safe substring
     *
     * @staticvar boolean $exists
     * @param string $str
     * @param int $start
     * @param int $length
     * @return string
     */
    static public function safeSubstr($str, $start, $length = null)
    {
        static $exists = null;
        if ($exists === null) {
            $exists = function_exists('mb_substr');
        }
        if ($exists) {
            // mb_substr($str, 0, NULL, '8bit') returns an empty string on PHP
            // 5.3, so we have to find the length ourselves.
            if (!isset($length)) {
                if ($start >= 0) {
                    $length = self::safeStrlen($str) - $start;
                } else {
                    $length = -$start;
                }
            }
            return mb_substr($str, $start, $length, '8bit');
        }
        // Unlike mb_substr(), substr() doesn't accept NULL for length
        if (isset($length)) {
            return substr($str, $start, $length);
        }
        return substr($str, $start);
    }
}
