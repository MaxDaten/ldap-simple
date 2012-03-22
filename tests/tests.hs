
import Test.HUnit
                      
-- TODO: move the tests in a testsuite
-- test the correctnes
ldapConformTest1 = TestCase (assertEqual 
    "resulting hash compare" 
    "mu0HUvs51z98teq6OiAA7cO9NuQsH4NjgpKsxg=="
    (ldapssha "This is a string" "MmMxZjgzNjM4MjkyYWNjNg=="))

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

tests = TestList [ TestLabel "ldap conformity test"         ldapConformTest1
                 , TestLabel "ldap conformity test"         ldapConformTest2
                 , TestLabel "ldap conformity test (utf)"   ldapConformTestUtf1
                 , TestLabel "ldap conformity test (utf)"   ldapConformTestUtf2
                 , TestLabel "ldap conformity test (utf)"   ldapConformTestUtf3
                 , TestLabel "ldap conformity test (utf)"   ldapConformTestUtf4
                 , TestLabel "ldap conformity test (utf)"   ldapConformTestUtf5
                 --, TestLabel "ldap conformity test (unicode)" ldapConformTestUnicode
                 ]

     
