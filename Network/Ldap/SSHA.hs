{-# LANGUAGE OverloadedStrings #-}
module Network.Ldap.SSHA 
    (
    slappasswd
    ) where


import qualified Data.Digest.Pure.SHA as SHA
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as L

import Data.Text.Lazy.Encoding (encodeUtf8)
import Data.ByteString.Base64 (encode)
import Data.ByteString.Lazy.Char8 (ByteString)
import Data.Text.Lazy (Text)

import System.IO
import System.Random



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
