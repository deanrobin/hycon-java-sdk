package com.hycon.HyconUtil;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.google.bitcoin.core.ECKey;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;

import com.google.bitcoin.core.AddressFormatException;
import com.google.bitcoin.core.Base58;
import com.google.protobuf.ByteString;
import com.hycon.proto.TxOuterClass;
import com.hycon.proto.TxOuterClass.Tx;
import com.rfksystems.blake2b.*;
import com.rfksystems.blake2b.security.Blake2bProvider;

import java.security.Security;

public class Utils {
	
	public Utils(){
		Security.addProvider(new Blake2bProvider());
	}
	
	public static String encodeHexByteArrayToString(byte[] ob) {
		return Hex.encodeHexString(ob);
	}
	
	public static byte[] decodeHexStringToByteArray(String str) throws DecoderException {
		return Hex.decodeHex(str.toCharArray());
	}
	
	public static byte[] blake2bHash(byte[] ob) throws NoSuchAlgorithmException {
		
		
		return MessageDigest.getInstance(Blake2b.BLAKE2_B_256).digest(ob);
	}
	
	public static byte[] blake2bHash(String ob) throws NoSuchAlgorithmException, DecoderException {
		
		
		return MessageDigest.getInstance(Blake2b.BLAKE2_B_256).digest(Hex.decodeHex(ob.toCharArray()));
	}
	
	public static String base58Encode(byte[] ob) {
		return Base58.encode(ob);
	}
	
	public static byte[] base58Decode(String ob) throws AddressFormatException {
		return Base58.decode(ob);
	}
	
	public byte[] publicKeyToAddress(byte[] publicKey) throws NoSuchAlgorithmException {
		byte[] hash = blake2bHash(publicKey);
		byte[] result = new byte[20];
		for(int i=12; i<32; ++i) {
			result[i-12] = hash[i];
		}
		
		return result;
	}
	
	public static String addresssCheckSum(byte[] arr) throws NoSuchAlgorithmException {
		byte[] hash = blake2bHash(arr);
		String str = base58Encode(hash);
		str = str.substring(0, 4);
		
		return str;
	}
	
	public String addressToString(byte[] publicKey) throws NoSuchAlgorithmException {
		return "H" + base58Encode(publicKey) + addresssCheckSum(publicKey);
	}
	
	public static byte[] addressToByteArray(String address) throws Exception {
		if(address.charAt(0) != 'H') {
			throw new Exception("Address is invalid. Expected address to start with 'H'");
		}
		
		String checkSum = address.substring(address.length() - 4, address.length());
		address = address.substring(1, address.length() - 4);
		byte[] out = base58Decode(address);
		
		if(out.length != 20) {
			throw new Exception("Address must be 20 bytes long");
		}
		
		String expectChecksum = addresssCheckSum(out);
		if(!expectChecksum.equals(checkSum)) {
			throw new Exception("Address hash invalid checksum " + checkSum + " expected " + expectChecksum);
		}
		
		return out;
		
	}
	
	public static long hyconfromString(String val) {
		if(val.equals("") || val == null) {
			return Long.valueOf("0");
		}
		
		if(val.toCharArray()[val.length() - 1] == '.') {
			val += "0";
		}
		
		String[] arr = val.split("\\.");
		
		long hycon = Long.valueOf("0");
		hycon = hycon + (Long.valueOf(arr[0]) * ((long)Math.pow(10, 9)));
		
		if(arr.length > 1) {
			arr[1] = arr[1].length() > 9 ? arr[1].substring(0, 9) : arr[1];
			long subCon = Long.valueOf(arr[1]) * ((long) Math.pow(10, 9 - arr[1].length()));
			hycon = hycon + subCon;
		}
		
		return hycon;
	}
	
	public static String hyconToString(long val) {
		long integer = val / Long.valueOf("1000000000");
		long sub = val % Long.valueOf("1000000000");
		
		if(sub == 0) {
			return String.valueOf(integer);
		}
		
		String decimals = String.valueOf(sub);
		while(decimals.length() < 9) {
			decimals = "0" + decimals;
		}
		
		while(decimals.charAt(decimals.length() - 1) == '0') {
			decimals = decimals.substring(0, decimals.length() - 1);
		}
		
		return String.valueOf(integer) + "." + decimals;
	}
}
