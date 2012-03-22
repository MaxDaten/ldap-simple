{-# LANGUAGE OverloadedStrings #-}
module Network.Ldap.SSHA where


import qualified Data.Digest.Pure.SHA as SHA
import qualified Data.ByteString.Char8 as B
import qualified Data.Text.Encoding as E
import qualified Data.ByteString.Lazy.Char8 as L
import qualified Data.ByteString.Base16 as B16
--import qualified Data.Text.Internal (TI)

import Data.Text.Lazy.Encoding (encodeUtf8, decodeUtf8)
import Data.ByteString.Base64 (encode, decodeLenient)
import Data.ByteString.Lazy.Char8 (ByteString)
--import Data.Text (Text)
import Data.Text.Lazy (Text, fromStrict)

import System.IO
import System.Random

import Test.HUnit


-- | 
ssha'' :: ByteString -> ByteString
ssha'' = SHA.bytestringDigest . SHA.sha1

-- | LDAP specific SSHA implementation
-- Takes a password and a salt and returns the LDAP conform sha1-hashed and salted password with
-- the appended salt
-- 
-- 1. The salt is appended to the raw unhased password
-- 2. The password ++ salt will be hashed with sha1
-- 3. The hashed value will be appended with the salt
-- in Hhaskell pseudocode: 
-- > ssha = sha1 (password ++ salt) ++ salt
ssha' :: ByteString -> ByteString -> ByteString
ssha' pass salt = L.append (ssha'' passSalt) salt
    where passSalt = L.append pass salt

ldapssha :: Text -> L.ByteString -> B.ByteString
ldapssha password hexSalt = encode $ B.concat $ L.toChunks $ ssha' (encodeUtf8 password) (hexSalt)


-- | like the the OpenLDAP slappasswd tool
-- currently only with ssha support
slappasswd :: Text -> IO B.ByteString
slappasswd pass = do 
    salt <- genSalt
    return $ B.append "{SSHA}" (ldapssha pass salt)


-- | Ispired by the 'Crypto.PasswordStore.genSaltDevURandom'
genSalt = genSaltDevURandom

-- | Generate a salt from @\/dev\/urandom@.
genSaltDevURandom :: IO L.ByteString
genSaltDevURandom = withFile "/dev/urandom" ReadMode $ \h -> do
                      rawSalt <- L.hGet h 8
                      return $ rawSalt

-- | test the correctnes
ldapConformTest1 = TestCase (assertEqual 
    "resulting hash compare" 
    "mu0HUvs51z98teq6OiAA7cO9NuQsH4NjgpKsxg=="
    (ldapssha "This is a string" "2c1f83638292acc6"))

ldapConformTest2 = TestCase (assertEqual 
    "resulting hash compare" 
    "eImy8C0G2O4u/nUmMwwCxn7zFbtcG+hVHjbUSw=="
    (ldapssha "abcd" "5c1be8551e36d44b"))
    
ldapConformTestUtf1 = TestCase (assertEqual 
    "resulting hash compare" 
    "7M+wAT09jxNmHtHKk6XmzbY10SKHr0gn3LeA7g=="
    (ldapssha "ä" "87af4827dcb780ee"))

ldapConformTestUtf2 = TestCase (assertEqual 
    "resulting hash compare" 
    "DQ7CKw0npl9eseqZFDKe4RHiSpGzrGmKL9+x3w=="
    (ldapssha "ß" "b3ac698a2fdfb1df"))
    
ldapConformTestUtf3 = TestCase (assertEqual 
    "resulting hash compare" 
    "F6jTB5EiL4A/kwLmdvzj4hfLQEQQfJTqM0WTSQ=="
    (ldapssha "äö" "107c94ea33459349"))
    
ldapConformTestUtf4 = TestCase (assertEqual 
    "resulting hash compare"
    "qt1xO8sLku3OV0Ff7EkWYXCH2QKx1XRi0CSPCw=="
    (ldapssha "äöüß#$&^^" "b1d57462d0248f0b"))
    
ldapConformTestUtf5 = TestCase (assertEqual 
    "resulting hash compare"
    "bRLDe85FraSKTWwlcFT70RPBOkulKSK6IME9vA=="
    (ldapssha "#µ€" "a52922ba20c13dbc"))
                  
{--
ldapConformTestUnicode = TestCase (assertEqual  
    "resulting hash compare" 
    "PIJ3se9+smm/FToYMOvj8yfvK5jG9tz1RZLJKg=="
    (ssha (encodeUtf8 "äöüß") (L.fromChunks [fst $ B16.decode "c6f6dcf54592c92a"])))
    --}
tests = TestList [ TestLabel "ldap conformity test"         ldapConformTest1
                 , TestLabel "ldap conformity test"         ldapConformTest2
                 , TestLabel "ldap conformity test (utf)"   ldapConformTestUtf1
                 , TestLabel "ldap conformity test (utf)"   ldapConformTestUtf2
                 , TestLabel "ldap conformity test (utf)"   ldapConformTestUtf3
                 , TestLabel "ldap conformity test (utf)"   ldapConformTestUtf4
                 , TestLabel "ldap conformity test (utf)"   ldapConformTestUtf5
                 --, TestLabel "ldap conformity test (unicode)" ldapConformTestUnicode
                 ]

{--
ssha :: Text -> Text -> B.ByteString
ssha pass salt = encode $ B.concat $ L.toChunks $ ssha' bPass bSalt
    where   bPass = encodeUtf8 $ pass
            bSalt = encodeUtf8 $ salt
--}
    