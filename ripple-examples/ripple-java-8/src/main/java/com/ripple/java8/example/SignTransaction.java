package com.ripple.java8.example;

import com.ripple.core.coretypes.AccountID;
import com.ripple.core.coretypes.Amount;
import com.ripple.core.coretypes.STObject;
import com.ripple.core.coretypes.uint.UInt32;
import com.ripple.core.types.known.tx.signed.SignedTransaction;
import com.ripple.core.types.known.tx.txns.Payment;
import com.ripple.crypto.ecdsa.Seed;
import io.github.novacrypto.bip39.SeedCalculator;

import java.security.SecureRandom;

import static com.ripple.java8.utils.Print.print;

/**
 * This example shows how to sign a transaction built using
 * the ripple-lib-java API and one already built in json.
 */
public class SignTransaction {
    public static void main(String[] args) {
        String rootWords ="engine state intact language property office margin climb shrimp tray letter number";
        byte[] seedtmp = new SeedCalculator().calculateSeed(rootWords, "");
        byte[] seedXrp = new byte[16];
        // modifyied by yx 2020-09-21
        //核心和关键是只截取最后16位数据，然后添加版本号和校验码再进行xrp的base58进行编码
        System.arraycopy(seedtmp, 64-16, seedXrp, 0, 16);
        Seed seedBip39 = new Seed(seedXrp);
        System.out.println("bip39 seed -> " + seedBip39);
        System.out.println("bip39 addr -> " + AccountID.fromSeedString(seedBip39+""));

        SecureRandom random = new SecureRandom();
        byte[] seedBytes = new byte[16];
        random.nextBytes(seedBytes);
        Seed seed = new Seed(seedBytes);
        System.out.println("rand seed -> " + seed);

        //----------通过随机秘密生成账户----------------
        AccountID act1 = AccountID.fromPassPhrase("yxadmingod");
        System.out.println("act from random pwd -> " + act1.address);

        //----------通过seed----------------
        AccountID act2 = AccountID.fromPassPhrase("ssStiMFzkGefDoTqgk9w9WpYkTepQ");
        System.out.println("act from seed -> " + act2.address);

        //--------以下为通过seed进行交易离线签名---------------------
        String secret = "spqqr1DLwYhJ72q619TaEggFF5znh";
        Payment payment = new Payment();

        // Put `as` AccountID field Account, `Object` o
        //发送者地址
        payment.as(AccountID.Account,     "rGZG674DSZJfoY8abMPSgChxZTJZEhyMRm");
        //接受者地址
        payment.as(AccountID.Destination, "rPMh7Pi9ct699iZUTWaytJUoHcJ7cgyziK");
        //发送金额
        payment.as(Amount.Amount,         "1000000000");
        //账户交易序号
        payment.as(UInt32.Sequence,       10);
        //交易手续费
        payment.as(Amount.Fee,            "10000");

        // Try commenting out the Fee, you'll get STObject.FormatException
        SignedTransaction signed = payment.sign(secret);
        // Sign doesn't mutate the original transaction
        // `txn` is a shallow copy
        if (signed.txn == payment)
            throw new AssertionError();

        // MessageFormat which does the heavy lifting for print gets confused
        // by the `{` and `}` in the json.
        print("The original transaction:");
        print("{0}", payment.prettyJSON());
        print("The signed transaction, with SigningPubKey and TxnSignature:");
        print("{0}", signed.txn.prettyJSON());
        print("The transaction id: {0}", signed.hash);
        print("The blob to submit to rippled:");
        print(signed.tx_blob);//提交该结果到区块即可完成交易广播

        // What if we just have some JSON as a string we want to sign?
        // That's pretty easy to do as well!
        String tx_json = payment.prettyJSON();
        signAgain(tx_json, secret, signed);
    }

    private static void signAgain(String tx_json,
                                  String secret,
                                  SignedTransaction signedAlready) {
        // fromJSON will give us a payment object but we must cast it
        Payment txn = (Payment) STObject.fromJSON(tx_json);
        SignedTransaction signedAgain = txn.sign(secret);
        // The hash will actually be exactly the same due to rfc6979
        // deterministic signatures.
        if (!signedAlready.hash.equals(signedAgain.hash))
            throw new AssertionError();
    }
}
