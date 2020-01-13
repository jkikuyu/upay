# UnionPay API
# Introduction

The API will receive union pay credit card transaction requests and return appropriate responses. Requests shall be for purchase, purchase cancellation, transaction query, pre-authorization, pre-authorization complete and pre authorization complete cancellation. 

# Overview

The UnionPay.php file consists of two parts. A Class UnionPay and and entry point that sets the environment and instantiates the class

# Setup 
In order to setup the packages run

~~~
composer install
~~~


# Configuration 
The following configuration is required prior to making request and is set in the .ENV file

| Attribute | Value |Comments|
| --------- | --------- | --------- |
| UPOP.MERCHANTID | 000000070000017<span></span> |Merchant identifier assigned to Company |
| UPOP.VERSION | 5.1.0 |  Version of used by UP gateway  |
| UPOP.ENCODING | UTF-8 | The character code applied to all string values|
| UPOP.SIGNMETHOD | 01 | Signature method used during encryption|
| UPOP.BIZTYPE | 000000 | The Type of Business 000301: Merchant-hosted, 000000: ExpressPay, 000902: Token payment, 001001: Mail Order Telephone Order  000201: SecurePay, 000701: Card-Present transaction,000802: AM remote payment 000902: Token payment, 001001: MOTO |
| UPOP.ACCESSTYPE | 0 | 0: Merchant direct access, 1: Acquirer access 2: Platform type merchant access
| UPOP.CHANNELTYPE | 08 | 07: Internet or 08: Mobile |
| UPOP.CURRENCYCODE | 156 |[ Currency Codes ]( https://www.iban.com/currency-codes)
| UPOP.CERTID| 69629715588 | The certificate ID that is used. It is preferable to have this as an environment variable |
| UPOP.PAYTIMEOUT | 3 | The time out period for pre-authorization |
| UPOP.SMSCODE | 111111 | SMS code is used in combination with account number in the absence of CVV, card expiry and phone number  |
| UPOP.FRONTURL | https://<span></span>ipay-staging.ipayafrica.com/upop/unionpaycbk/frontRcvResponse.php | The callback URL that receives the notice from UnionPay's foreground | 
| UPOP.BACKURL | https://ipay-staging<span></span>.ipayafrica.com/upop/unionpaycbk/backRcvResponse.php | the address that background can receive the notice from UnionPay's foreground, and extranet access right should be granted.
| UPOP.SIGNCERT.PATH|certs/test/acp_test_sign.pfx| the private key for request before dispatch |
| UPOP.SIGNCERT.PWD|000000| The password required to use private key |
| UPOP.SIGNCERT.TYPE|PKCS12| The public ke<span></span>y cryptography standard used |
| UPOP.ENCRYPTCERT.PATH|certs/test/acp_test_root.cer | The root certificate path
|UPOP.MIDDLECERT.PATH | certs/test/acp_test_middle.cer | The intermidiary certificate path is used for certificate chaining |
| UPOP.TXNTYPE|01| Types of transaction processing purchase, pre-authorization, refund
| UPOP.TXNSUBTYPE|01| 01: Purchase, to differentiate the front-end purchase or back-end purchase through transaction request URL, 02: MOTO, 05: Purchase with, authentication, 09: Online QRC Payment |
| UPOP.ALG | sha256WithRSAEncryption | The encryption algorithm |

# Production Certificates
These certificates are located in the folder
~~~
unionpay/certs
~~~
# The base URL shall be as shown 
~~~~
/unionpay
~~~~

# Headers

** Content-Type :** application/json

# POST Purchase
A purchase request 
#### Request
```json
{
    "type": "1",
    "card": "6250947000000014",
    "orderId": "IPAY2020083",
    "txnAmt": 7000,
    "txnTime": "20200107131402",
    "cvn2": "123",
    "expiry": "3012",
    "phoneno": "13552535506"
}
```

| attribute | Description |Type | Requirement |
| --------------- | --------------- | --------------- |
| type| Transaction Type | Numeric | M |
| card| Credit card number | String | M |
| orderId| Order id that is unique | String |  M |
| txnAmt| Transaction amount in cents| Numeric |  M |
| txnTime| Time when transaction is taking place | String | M |
| smsCode| SMS code sent to customer phone | String | C |
| cvn | card verification number | String | C |
| expiry | Card expiry YYMM | String | C |
| phoneno |Customer phone number used  | String | C |

### Transaction Types
The following types are used to determine the transaction processing operation to be carried out

|Type|Description|
| ---------- | ---------- |
| 1 | Purchase |
| 2 | CANCELPURCHASE |
| 3 | REFUND |
| 4 | PREAUTH |
| 5 | CANCELPREAUTH |
| 6 | COMPLETEPREAUTH |
| 7 | CANCELCOMPLETEPREAUTH |
| 8 | RECURRING |
| 9 | QUERY |

#### Response (application/json)

A json response is returned as follows

```json
{
"status":"200",
"description":"OK",
"queryId":"402001081314022846518",
"respCode":"00"
>
}
```
| attribute | Description |
| --------------- | --------------- | 
| status| Response code  | 
| description| Response description | 
| queryId| Query idenfier used to search transaction |  
| respCode| Specific union pay response code  | 



# POST Preauth


#### Request (application/json)