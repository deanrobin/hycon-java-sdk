# Hycon Java SDK

- This sdk can create its own address with the private key, and generate a hex string with the signature transaction.


### **How can I use this project ?**

#### 1. getPrivateKey
- You can get a new private key. It's safety and private.
- You need use private key for get address

#### 2. getAddress
- You need provide your private key, and this will return address, like "Hxxxx....".

#### 3. signTransaction
- Parameters include two address, transfer amount, fee and your private key.
- There are three method for it. You can choose which you want.
- Result is an array of strings of length 2 ,first is hex String for signed transaction, second is recovery, maybe is 0 or 1.
- You can use those parameters and result, to send HYC client "/api/v1/tx/" to broadcast transaction.
- *By the way, networkId is 'hycon'.(If you know hycon used to be hard forked)*
  
<br/>
<br/>
  
   
---

### **Others**

- [x] If you have any question, you can submit in "issue".
- [x] Thanks to the help provided by the HYC project and people.
- [x] If this help you, please give me a star ^.^


