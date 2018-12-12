package com.hycon.HyconUtil;

import java.math.BigInteger;

import com.google.bitcoin.core.Base58;
import com.google.bitcoin.core.ECKey;
import com.google.protobuf.ByteString;
import com.hycon.proto.TxOuterClass;
import org.apache.commons.codec.DecoderException;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;

/**
 * @author Dean
 *
 */
public class HyconHelper {
    private static final String H = "H";
    private static final String FEE = "0.000000001";

    /**
     * Use private key to get address.
     * @param privateKey
     * @return Hyc address
     * @throws DecoderException
     */
    public static String getAddress(String privateKey) throws DecoderException {
        ECKey ecKey = new ECKey(new BigInteger(1, Utils.decodeHexStringToByteArray(privateKey)), null, true);
        byte[] pubKeyBytes = ecKey.getPubKey();

        byte [] result = new byte[32];
        Blake2bDigest blake2bDigest3 = new Blake2bDigest(null, result.length, null,null);
        blake2bDigest3.update(pubKeyBytes,0,pubKeyBytes.length);
        blake2bDigest3.doFinal(result,0);

        byte[] preAddress = new byte[20];
        for (int i = 12; i < 32; i++) {
            preAddress[i - 12] = result[i];
        }

        String preA = Base58.encode(preAddress);

        byte[] preCheckSum = new byte[32];
        Blake2bDigest blake2bDigest4 = new Blake2bDigest(null, preCheckSum.length, null,null);
        blake2bDigest4.update(preAddress,0, preAddress.length);
        blake2bDigest4.doFinal(preCheckSum,0);

        String preB = Base58.encode(preCheckSum).substring(0, 4);

        String address = H + preA + preB;
        return address;
    }

    /**
     * signed transaction, the transaction consists of these parameters
     * networkid is 'hycon', for prevent heavy mine attacks
     *
     * you can get this method result String[2] , to use hyc client http api "/api/v1/tx/"
     *
     * @param fromAddress transaction originator address
     * @param toAddress transaction get coin address
     * @param amount coin, such as 0.01
     * @param minerFee fee, recommend 0.000000001
     * @param nonce nonce, like eth, the number of fromaddress transaction, first transaction is 1, then nonce = nonce +1
     * @param privateKey private key, the same string like method getAddress()
     * @return String[2], String[0] is hex for signed transation, and String[1] is recovery
     * @throws Exception
     */
    public String[] signTx(String fromAddress, String toAddress, String amount, String minerFee,
                           int nonce, String privateKey) throws Exception {
        byte[] from = Utils.addressToByteArray(fromAddress);
        byte[] to = Utils.addressToByteArray(toAddress);

        TxOuterClass.Tx.Builder txBuilder = TxOuterClass.Tx.newBuilder();
        txBuilder.setFrom(ByteString.copyFrom(from));
        txBuilder.setTo(ByteString.copyFrom(to));
        txBuilder.setAmount(Utils.hyconfromString(amount));
        txBuilder.setFee(Utils.hyconfromString(minerFee));
        txBuilder.setNonce(nonce);

        TxOuterClass.Tx.Builder newTxBuilder = TxOuterClass.Tx.newBuilder(txBuilder.build());
        newTxBuilder.setNetworkid("hycon");
        TxOuterClass.Tx newTx = newTxBuilder.build();
        byte[] newTxData = newTx.toByteArray();
        byte[] newTxHash = Utils.blake2bHash(newTxData);

        ECKeyPair ecKeyPair = ECKeyPair.create(Utils.decodeHexStringToByteArray(privateKey));
        Sign.SignatureData newSignatureData = Sign.signMessage(newTxHash, ecKeyPair, false);
        String newSignature = Utils.encodeHexByteArrayToString(newSignatureData.getR()) +
            Utils.encodeHexByteArrayToString(newSignatureData.getS());
        String newRecovery = String.valueOf(newSignatureData.getV() - 27);

        String[] result = new String[2];
        int index = 0;
        result[index++] = newSignature;
        result[index++] = newRecovery;

        return result;
    }

    /**
     * see method signTx
     */
    public String[] signTx(String fromAddress, String toAddress, String amount, int nonce, String privateKey)
        throws Exception {
        return signTx(fromAddress, toAddress, amount, FEE, nonce, privateKey);
    }
}
