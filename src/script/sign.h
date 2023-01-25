// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2016-2019 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGN_H
#define BITCOIN_SCRIPT_SIGN_H

#include "script/interpreter.h"

class CKeyID;
class CKeyStore;
class CScript;
class CTransaction;

struct CMutableTransaction;

/** Virtual base class for signature creators. */
class BaseSignatureCreator {
protected:
    const CKeyStore* keystore;

public:
    BaseSignatureCreator(const CKeyStore* keystoreIn) : keystore(keystoreIn) {}
    const CKeyStore& KeyStore() const { return *keystore; };
    virtual ~BaseSignatureCreator() {}
    virtual const BaseSignatureChecker& Checker() const =0;

    /** Create a singular (non-script) signature. */
    virtual bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode) const =0;
};

/** A signature creator for transactions. */
class TransactionSignatureCreator : public BaseSignatureCreator {
    const CTransaction* txTo;
    unsigned int nIn;
    int nHashType;
    const TransactionSignatureChecker checker;

public:
    TransactionSignatureCreator(const CKeyStore* keystoreIn, const CTransaction* txToIn, unsigned int nInIn, int nHashTypeIn=SIGHASH_ALL);
    const BaseSignatureChecker& Checker() const { return checker; }
    bool CreateSig(std::vector<unsigned char>& vchSig, const CKeyID& keyid, const CScript& scriptCode) const;
};

/** Produce a script signature using a generic signature creator. */
bool ProduceSignature(const BaseSignatureCreator& creator, const CScript& scriptPubKey, CScript& scriptSig, bool fColdStake);

/** Produce a script signature for a transaction. */
bool SignSignature(const CKeyStore& keystore, const CScript& fromPubKey, CMutableTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL, bool fColdStake = false);
bool SignSignature(const CKeyStore& keystore, const CTransaction& txFrom, CMutableTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL, bool fColdStake = false);

/** Combine two script signatures using a generic signature checker, intelligently, possibly with OP_0 placeholders. */
CScript CombineSignatures(const CScript& scriptPubKey, const BaseSignatureChecker& checker, const CScript& scriptSig1, const CScript& scriptSig2);

/** Combine two script signatures on transactions. */
CScript CombineSignatures(const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn, const CScript& scriptSig1, const CScript& scriptSig2);

/** An interface to be implemented by keystores that support signing. */
 class SigningProvider
 {
 public:
     virtual ~SigningProvider() {}
     virtual bool GetCScript(const CScriptID &scriptid, CScript& script) const { return false; }
     virtual bool GetPubKey(const CKeyID &address, CPubKey& pubkey) const { return false; }
     virtual bool GetKey(const CKeyID &address, CKey& key) const { return false; }
 };

 extern const SigningProvider& DUMMY_SIGNING_PROVIDER;

 class PublicOnlySigningProvider : public SigningProvider
 {
 private:
     const SigningProvider* m_provider;

 public:
     PublicOnlySigningProvider(const SigningProvider* provider) : m_provider(provider) {}
     bool GetCScript(const CScriptID &scriptid, CScript& script) const;
     bool GetPubKey(const CKeyID &address, CPubKey& pubkey) const;
 };

 struct FlatSigningProvider final : public SigningProvider
 {
     std::map<CScriptID, CScript> scripts;
     std::map<CKeyID, CPubKey> pubkeys;
     std::map<CKeyID, CKey> keys;

     bool GetCScript(const CScriptID& scriptid, CScript& script) const override;
     bool GetPubKey(const CKeyID& keyid, CPubKey& pubkey) const override;
     bool GetKey(const CKeyID& keyid, CKey& key) const override;
 };

 FlatSigningProvider Merge(const FlatSigningProvider& a, const FlatSigningProvider& b);

#endif // BITCOIN_SCRIPT_SIGN_H
