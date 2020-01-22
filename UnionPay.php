<?php
namespace Unionpay;
require_once('vendor/autoload.php');
use \Monolog\Logger as Logger;
use \Monolog\Handler\StreamHandler as StreamHandler;
use \Dotenv\Dotenv as Dotenv;
/**
* author @jude@ipayafrica.com
* date: 12/11/2019
* The unionpay class is specific to Union Pay credit cards. The class receives a request in json format. 
* A determination is made as to the payment type. Validations are carried out. Data is encrypted using
* private and public keys and forwarded to the payment processor. On receipt of response. The public key and
* signature are validated. A successful response means that the request was successful. The payment types
* include purchase, purchase cancellation, preauthorization , preauthorization complete, preauthorization
* complete cancel and refund 
*
*
**/
class UnionPay{
	/* transaction Types*/
	const PURCHASE = 1;
	const CANCELPURCHASE  = 2;
	const REFUND  = 3;
	const PREAUTH = 4;
	const CANCELPREAUTH=5;
	const COMPLETEPREAUTH=6;
	const CANCELCOMPLETEPREAUTH=7;
	const RECURRING=8;
	const QUERY=9;
	/* variables required unionpay request creation*/
	
	
	//certificates
	const SIGNCERTPATH="certs/test/acp_test_sign.pfx";
	const ENCRYPTCERTPATH="certs/test/acp_test_enc.cer";
	const ROOTCERTPATH="certs/test/acp_test_root.cer";
	const MIDDLECERTPATH="certs/test/acp_test_middle.cer";
	//URLS
	//const BACKURL="https://ipay-staging.ipayafrica.com/upop/unionpaycbk/backRcvResponse.php";
	const BACKTRANSURL = "https://gateway.test.95516.com/gateway/api/backTransReq.do";
	const SINGLEQUERYURL="https://gateway.test.95516.com/gateway/api/queryTrans.do";
	private $backUrl="https://ipay-staging.ipayafrica.com/upop/unionpaycbk/backRcvResponse.php";
	private $frontUrl="https://ipay-staging.ipayafrica.com/upop/unionpaycbk/frontRcvResponse.php";
	private $version="5.1.0";
	private $encoding ="UTF-8";
	private $signMethod="01";
	private $bizType = "000000";
	private $accessType ="0";
	private $channelType ="08";
	private $merId="000000070000017";
	private $port=443;
    protected $signCertType= "PKCS12";

	/*identifier of certificate used for encryption of data */
    private $certId;

	private $currencyCode;


	/*to store the basic required items when making a request */
	private $orderId;
	private $txnTime;
	private $txnAmt;

	public $log;

	/** Encryption public key and certificate for sensitive information */
	private $encryptCert = null;

	
	
	 /** Path of signed certificate. */
    //protected $signCertPath;
    /** Password of signed certificate. */
    protected $signCertPwd;
    /** Type of signed certificate. */
    /** Path of encrypted public key certificate. */
    //public $encryptCertPath;
    /** Authenticate the catalog of signed public key certificates. */
    //protected $validateCertDir;
    /** Read the catalog of specified signed certificates according to client codes. */
    //protected $signCertDir;
    /** Security key (used in calculation of SHA256 and SM3) */
    //protected $secureKey;
	/** algorithm for signing data**/
	//protected $alg;
    
	private static $keystore = null;
	/** Encryption public key for magnetic tracks */
	private static $encryptTrackKey = null;
	/** Verify the messages, signatures, and certificates returned from China UnionPay. */
	private static $validateCert = null;
	/** Authenticate the signatures of intermediate certificates */
	private static $middleCert = null;
	/** Authenticate the signatures of root certificates */
	private static $rootCert = null;
    
	private static $instance;

	private $frontRequestUrl;


	/** Path of intermediate certificates  */
	private $middleCertPath;
	/** Path of root certificates  */
	private $rootCertPath;
	/** For whether to verify the CNs of the certificates for verifying certificates, all certificates except the ones for which this parameter has been set to false should be authenticated.  */
	private $ifValidateCNName = true;
	/** For whether to authenticate the https certificate, all certificates need not to be authenticated by default.  */
	private $ifValidateRemoteCert = false;
	/*url used to make request to unionpay server*/
	public $backTransUrl;

	public function __construct(){
	/*
		set default values during class instantiation
	*/

		error_reporting(E_ALL);
		ini_set('display_errors', TRUE);

		ini_set('display_startup_errors', TRUE);
		// load the dotenv file
		$dotenv = Dotenv::createImmutable(__DIR__);
		$dotenv->load();
		$this->getLogFile("UPOP");
		$this->smsCode=getenv('UPOP.SMSCODE');
		$this->certId = getenv('UPOP.CERTID');
        $this->signCertPwd=getenv('UPOP.SIGNCERT.PWD');



	}
	private function getSignature($merged_data=null){
		$success = self::initCert();
		$signedData="";
		try{
		if ($success){
			$strData = self::convertToString($merged_data);

			$pkey = self::$keystore['pkey'];
			$signedData = self::generateSignature($pkey, $strData);
			
		}
		else
			$this->log->error("unable to read file");

			
			throw new \Exception("Error, contact system administrator");
		}
		catch(\Exception $e){
			$this->log->error($e->getMessage());
		}
		return $signedData;
	}
	private function initCert(){
		$success =false;

        if ($this->signCertType =='PKCS12'){
			try{
				if ($cert_store = file_get_contents(self::SIGNCERTPATH)) {

						if (openssl_pkcs12_read($cert_store, self::$keystore, $this->signCertPwd)){
						   $this->log->info("Signed Certicate loaded Successfully");
							$success=true;
						}
						else{
							$this->log->error("unable to read file");

							throw new \Exception("Error, contact system administrator");

						}

				}
				else{
					$this->log->error("unable to read file");
					throw new \Exception("Error, contact system administrator");
				}
			}
			catch(\Exception $e){
				$this->log->error($e->getMessage());
			}
		}
		return $success ;
	}

	private function generateSignature($privateKey, $data=null){
		/* Ensure raw data is encoded using UTF-8, apply hasing. IMPORTANT that resulting hash is encoded 
		 * again using UTF-8
		 */
		//echo "data to be signed:". $data ."\r\n";
		$utf8=   utf8_encode ($data);

		$enc = self::generateHash($data);
		//echo "hash:". $enc ."\r\n";
		$signature = self::signData($enc, $privateKey);
		
		$b64 = base64_encode($signature);

    return $b64;
	}
	private function generateHash($utf8){
		//function used both for request and response. Response contain chinese characters and utf8_encode not applicable
		$sha256 = hash ("sha256",$utf8);
		$utf8_enc=   utf8_encode ($sha256); //enchode the hashed data
	return $utf8_enc; 	
	}
	private function signData($enc , $privateKey){
		$alg ='sha256WithRSAEncryption';
		$signature = "";
		try{
			if (openssl_sign ( $enc , $signature ,  $privateKey, $alg)){
				//success

			}
			else{
				$this->log->error("unable to read cert file");
				throw new \Exception("Error, contact system administrator");
			}
		}
		catch(\Exception $e){
			$this->log->error($e->getMessage());
		}
	return $signature;
		
	}


    private function curlPost(array $data, $url,$port){
		//echo "url:". $url;

		$headers = ["Content-type:application/x-www-form-urlencoded;charset=UTF-8"];
		$request_time = new \DateTime();
		$strData = "";
		$output="";
		try{
			if(!is_string($url)){
				$this->log->error('URL must be a string!');
				throw new \InvalidArgumentException('Error, contact system administrator');
			}
			else{
				foreach($data as $key => $value) {
					$strData.= $key."=";

						$strData.= urlencode($value);

						$strData.="&";

				}
				$strData = substr($strData,0,strlen($strData)-1);



				//init curl
				$curl = curl_init();


				curl_setopt($curl, CURLOPT_URL, $url);
				curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
				curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
				//set request headers
				curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
				curl_setopt($curl, CURLOPT_PORT, $port);

				//request method is POST
				curl_setopt($curl, CURLOPT_POST, 1);
				//request body
				curl_setopt($curl, CURLOPT_POSTFIELDS, $strData);


				//return transfer response as string to the $curl resource
				curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

				//output verbose info
				curl_setopt($curl, CURLOPT_VERBOSE, 1);

				$output = curl_exec($curl);
				//Utils::infoMsg($output);
				$this->log->info("response received:". $output);
				//echo $output;
			}

		}
		catch(\Exception $e){
				$this->log->error($e->getMessage());
		}

	return $output;

	}
	
	private function encryptCardData($cardDetails){
		/*
			This function excrypts card information using a public key
		*/
		$encryptCert= self::getEncryptCertPath();

        $publickey = openssl_pkey_get_public($encryptCert);
        $keyData = openssl_pkey_get_details($publickey);
	    $key=$keyData['key'];
		openssl_public_encrypt($cardDetails, $enc, $key, OPENSSL_PKCS1_PADDING);   
    	$cardEnc = base64_encode($enc);
	return $cardEnc;	
	}
	
	public function encryptedCertId(){
		/*
			This funcitons retrieves the certificate identifier
		*/
		$encryptCert= self::getEncryptCertPath();
		
		$data=openssl_x509_parse($encryptCert,true);
		$serialNo = $data['serialNumber'];
	return $serialNo;
	}
	private function getEncryptCertPath(){
	/*
		Function to get the certificate to use for encryption
	*/
		$encrypted="";
		try{
			if ($enCertPath = file_get_contents(self::ENCRYPTCERTPATH)) {

			}
			else{
				$this->log->error("unable to read cert file");
				throw new \Exception("Error: Unable to proceed\n");

			}
		}
		catch(\Exception $e){
			$this->log->error($e->getMessage());
		}
		return $enCertPath;
	}

	private function encryptCustomerInfo(array $customerInfo, $card_number){
	/*	Function receives card details and card number. If pin is provided as part of input then this is 		base64 encoded with card number otherwise only card details only are encoded
	*/
		foreach ($customerInfo as $key=>$value){
			if($key==="phoneNo" || $key==="cvn" || $key==="expired"){
				$strData.= $key."=".$value."&";


			}
			else{ 
				if ($key==="pin" && strlen(trim($card_number))>0){
					// to be implemented according to SDK
				}
				$strData = $key."=".$value."&";
			}

		}
	    $strData = "{" . substr($strData,0,strlen($strData)-1) . "}";

	    $customerInfoEnc = base64_encode($strData);
		//echo "customer info enc:" . $customerInfoEnc;
	 return $customerInfoEnc;
	}
	protected function decryptCustomerInfo($package, $pass){
		openssl_pkcs12_read($cert_store, $certs, $pass);
		$res=$certs['pkey'];
		$b64dec = decodeSign($package);

		openssl_private_decrypt($b64dec,$decrypted,$res);
		//echo "plain text ". $decrypted."<br />";

	}

	
	private function isPubKeyCertValid($pubCertStr){
		$cert = openssl_x509_parse($pubCertStr);
		$isValid = "True";
		
		if( $cert['validFrom_time_t'] > time() || $cert['validTo_time_t'] < time() )
			$isValid = "false";
		else{
			//self::initMiddleCert();
			//self::initRootCert();
			$intermediateCerts=[self::MIDDLECERTPATH, self::ROOTCERTPATH];
			try{
				$success = openssl_x509_checkpurpose($pubCertStr,X509_PURPOSE_ANY,$intermediateCerts);
				if (!$success){
					$isValid="False";
					throw new \Exception("Certificate validation failed");
				}
			}
				
			catch(Exception $e){
				$this->log->error($e->getMessage());

			}

		}
		
	return $isValid;
	}

	private function isDataValid(array $ares){
		$signature = $ares["signature"];

		unset($ares['signature']);
		//echo "<br />";
		//print_r($ares);
		$pubKeyStr=  $ares["signPubKeyCert"];
		$strData = self::convertToString($ares);
		$strDataEnc = self::generateHash($strData);
		$decodedStr = self::decodeSgn($signature);
		$pubkey= openssl_x509_read($pubKeyStr);
		$alg = "sha256WithRSAEncryption";
		$success = false;
		
		if (openssl_verify($strDataEnc,$decodedStr,$pubkey,$alg )){
			$success=true;
		}
		return $success;

	}
	
	
	private function decodeSgn($pkg){
		//echo "package:". $pkg;
		$decodedPkg  = base64_decode($pkg);
	 return $decodedPkg;
		
	}

	private function processRequest($merged_data=null, $requiredData=null){
	/*

	* i.  validate merged array
	* ii.   get keystore
	* iii. generate signature
	*/
	$oData = (object) $merged_data; //make object for validation 
	$isValid = self::isRequestValid($oData,$requiredData);

	if ($isValid){
		$signature	= self::getSignature($merged_data);
	}
	else{
		return $isValid;
	}
	return $signature;

	}	

	private function convertToString($merged_final=null){
        $strData = null;
        ksort($merged_final);
		//print_r($recd);

            foreach($merged_final as $key => $value) {
                $strData.= $key."=".$value."&";

            }
        $strData = substr($strData,0,strlen($strData)-1);
		return $strData;
	}

    private function isRequestValid($recd=null, $required=null){
        /**
        
        @param recd data received from requester
        @param required fields required for processing
        
        **/
        $valid = false;
        try{
            if(empty($recd)){
                throw new \InvalidArgumentException('Invalid request made');
            }
            $valid = self::validateRequest($recd, $required);
        }
        catch(InvalidArgumentException $e){
           	$this->log->error($e->getMessage());
        }
        return $valid;
    }


	private function initiateRequest(array $reqData, $url, $port){
		$response = self::curlPost($reqData, $url, $port);

		return $response;

	}
    
	private function validateRequest($raw_input, array $required_params){
	/*
		Validation of request to ensure it has the mandatory fields required
	*/
		$res_arr = null;
        $res_obj = null;
		try{
			if($raw_input){
				foreach($required_params as $param){
					//take not that empty("0") evaluates to a false;
					if(!property_exists($raw_input, $param) || (empty($raw_input->$param) 
						&& strlen($raw_input->$param)== 0) || !(is_string($raw_input->$param) || is_int($raw_input->$param))){
						die($param . ' is required');
					}
					else{
						$res_arr[$param] = $raw_input->$param;
					}
				}
				$res_obj = (object) $res_arr;
			}
			else{
				throw new \Exception('The following parameters are required ' . json_encode($required_params));
			}
		}
		catch(\Exception $e){
			$this->log->error($e->getMessage());
		}
    return $res_obj;
    }


	private function getDefaultContent(){
		
        $content = array(
            "version"=>$this->version,
            "encoding"=>$this->encoding,
            "signMethod" =>$this->signMethod, 
            "bizType"=>$this->bizType,
            "accessType"=>$this->accessType,
            "merId"=>$this->merId,
            "certId" => $this->certId,
        );
    
        return $content;
    }
	private function getPurchaseContent(){
	/*
		Additional fields required for making purchase, purchase cancellation, preauthorization  requests. The data is stored in the .env file
	*/
		 $content = array(
		"channelType"=>$this->channelType,
		"backUrl"=> $this->backUrl
		 );
			 
	return $content;
	}
	private function getRefundContent(){
		 $content = array(
		"channelType"=>$this->channelType,
		"backUrl"=> $this->backUrl
		 );
			 
	return $content;
	}
	private function getPreauthContent(){
		 $content = array(
		"channelType"=>$this->channelType,
		"frontUrl"=> $this->frontUrl,
		"backUrl"=> $this->backUrl
		 );
			 
	return $content;
	}
    private function getRequiredFlds(){
        $required_data = [
            'version',
            'encoding',
            'signMethod',
            'txnType',
            'txnSubType',
            'bizType',
            'accessType',
            'merId',
            'orderId',
            'txnTime',
            'certId'
        ];
        return $required_data;
    }
  /*  public function getBasicInputsRequired(){
	
		Return an array of basic fields that are required for any unionpay transaction. These fields include
		order id , time transaction in taking place and type of transacton such as purchase, preauthorization, refund,
		Three items
	
		
        //$requiredInputs=['orderId','txnTime','type'];
		$requiredInputs=['type'];
		return $requiredInputs;
    }*/
	
    private function getLogFile($tag="iPay"){
		
        $dirname = getenv('LOGDIR');

       // echo "dir: ". $dirname;}
        try{
			if(!is_string($dirname)){
				throw new \InvalidArgumentException('dirname must be a string');
			}
			else{
				// $logs    = (is_array($logs))? json_encode($logs, JSON_PRETTY_PRINT): (string)$logs;

				$dir = $dirname;

				$base_dir = dirname(__dir__).'/';

				$save_dir = $base_dir.$dirname;

				$dir_exists = (file_exists($save_dir) && is_dir($save_dir));

				if(!$dir_exists){
					if(!mkdir($save_dir, 0755, true)){
						$this->log->error("Unable to create directory");
						throw new \Exception("Error, contact system administrator");
					}
				}
				$dir = $save_dir;
				$logFile = $dir."/".date("Y-m-d").'.log';
				$this->log = new Logger($tag);
				$this->log->pushHandler(new StreamHandler($logFile , Logger::INFO));

			}
		}
		catch (\Exception $e){
			$this->log->error($e->getMessage());
		}
    }

	public function makeRequest($dataRecd){

		$isRequestJson = (json_decode($dataRecd) != NULL) ? true : false;

		try{
			if ($isRequestJson){
				$requiredUserData = ['type'] ;// inital required input that has to be present to determine transaction processing
				$json = json_decode($dataRecd); 
				//check that json request has the basic required inputs. Further validation will be done for each transation type
				// the initial validation of json input in order to determine which task to perform
				$isValid = $this->validateRequest($json,$requiredUserData);


				if ($isValid){

					$class = null;
					// fields required are for de
					$requiredFlds = $this->getRequiredFlds();
					$url = self::BACKTRANSURL;
					switch ($json->type){
						case self::PURCHASE:
							// purchase
							//$var = 'Purchase';
							$txntype="01";
							$txnSubType="01";
							$encryptedCertId = $this->encryptedCertId();
							$combined=[];
							$requiredUserData = ['card','cvn','expiry','phoneno','txnAmt','txnTime',"currency","orderId"];
							$isValid = $this->validateRequest($json,$requiredUserData);
							if ($isValid){
								if($json->card===""){
									$this->log->error("Please provide card details");
									throw new \Exception("Error, contact system administrator");

								}
								else{

									if($json->expiry==="" && $json->cvn==="" && $json->phoneno==="" && $json->card){
											$requiredUserData = ["smsCode"];
											$this->validateRequest($json,$requiredUserData);

											if ($json->smsCode===""){
												$this->log->error("Please provide card details");

												throw new \Exception("Error, contact system administrator");

											}
											else{
												$customerInfo =["smsCode"=>  $this->smsCode];
											}
										}
										else{

											$cardDetails ="expired=".$json->expiry."&cvn2=". $json->cvn. "&phoneNo=". $json->phoneno;
											// card details such as expiry month, year and cvv encrypted seperately from card number 
											$encryptedInfo = $this->encryptCardData($cardDetails);
											$encryptedCard = $this->encryptCardData($json->card);
											//incase of presence of SMS code functionality it is combined with encrypted card details
											$customerInfo = ["smsCode"=>  $this->smsCode, "encryptedInfo"=>$encryptedInfo];
										}
									$encryptedCustomerInfo =  $this->encryptCustomerInfo($customerInfo,$json->card);
									$customerData = ["accNo"=>$encryptedCard, "encryptCertId"=>$encryptedCertId,"customerInfo"=>$encryptedCustomerInfo,"txnAmt"=> $json->txnAmt,"currencyCode"=>$json->currency];
									$purchaseContent = $this->getPurchaseContent();
									$combined = array_merge($purchaseContent,$customerData);
									// add additional fields for validation 
									array_push($requiredFlds,'channelType','backUrl');
								}
							}
							else{
								throw new \Exception("Error, contact system administrator");

							}
							break;
						case self::CANCELPURCHASE:
							//$var = 'PurchaseCancel';
							//$url = $this->backTransUrl;

							$txntype ="31";
							$txnSubType="00";
							$requiredUserData = ["txnAmt","txnTime","currency",'serialno'];
							$isValid = $this->validateRequest($json,$requiredUserData);
							if($isValid){
								$customerData = ["origQryId"=>$json->serialno, "txnAmt"=> $json->txnAmt,"currencyCode"=>$json->currency];
								$purchaseContent = $this->getPurchaseContent();
								$combined = array_merge($purchaseContent,$customerData);
								array_push($requiredFlds,'channelType','backUrl');
							}
							else{
								throw new \Exception("Error, contact system administrator");

							}

							//purchase Cancel
							break;
						case self::REFUND:
							// refund
							//$url = $this->backTransUrl;

							$txntype = "04";
							$txnSubType = "00";
							$customerData = ["origQryId"=>$json->serialno, "txnAmt"=> $json->txnAmt];
							$purchaseContent = $this->getRefundContent();
							$combined = array_merge($purchaseContent,$customerData);
							array_push($requiredFlds,'txnAmt','channelType','backUrl','origQryId');


							break;
						case self::PREAUTH:
							//PreAuth
							//$url = $this->backTransUrl;

							$txntype="02";
							$txnSubType="01";

							$duration = "3";
							$requiredUserData = ['card','cvn','expiry','phoneno','txnAmt','txnTime',"currency","orderId"];
							$isValid = $this->validateRequest($json,$requiredUserData);
							if ($isValid){
								$time = new \DateTime(date("Y-m-d H:i:s"));
								$timezone = new \DateTimeZone('Africa/Nairobi');
								$time->setTimezone($timezone);
								//echo "time: ".$time->format('Y-m-d H:i');
								//echo 'duration='.$txnSubType;
								$time->add(new \DateInterval('PT' . $duration . 'M'));

								$payTimeOut = $time->format('YmdHis');
								if($json->expiry==="" && $json->cvn==="" && $json->phoneno===""){
									if ($json->smsCode===""){
										new \Exception("Error, contact system administrator");

									}
									else{
										$customerInfo =["smsCode"=>  $this->smsCode];
									}
								}
								else{
									$cardDetails ="expired=".$json->expiry."&cvn2=". $json->cvn. "&phoneNo=". $json->phoneno;
									$encryptedInfo = $this->encryptCardData($cardDetails);

									$customerInfo = ["encryptedInfo"=>$encryptedInfo];
								}
								$encryptedCard = $this->encryptCardData($json->card);
								$encryptedCertId = $this->encryptedCertId();
								$encryptedCustomerInfo =  $this->encryptCustomerInfo($customerInfo,$json->card);
								$customerData = ["accNo"=>$encryptedCard, "encryptCertId"=>$encryptedCertId,"customerInfo"=>$encryptedCustomerInfo,"txnAmt"=> $json->txnAmt,"currencyCode"=>$json->currency, "payTimeout"=>$payTimeOut];

								//$customerData = [ "txnAmt"=> $json->txnAmt,"payTimeout"=>$payTimeOut];
								$purchaseContent = $this->getPreauthContent();
								$combined = array_merge($purchaseContent,$customerData);
								array_push($requiredFlds,'txnAmt','channelType','backUrl','frontUrl', 'payTimeout');
							}
							else{
								throw new \Exception("Error, contact system administrator");
			
							}


							break;
						case self::CANCELPREAUTH:

							$txntype="32";
							$txnSubType="00";


							$requiredUserData = ["txnAmt","txnTime","orderId","serialno","currency"];
							$isValid = $this->validateRequest($json,$requiredUserData);
							if($isValid){
								$customerData = ["origQryId"=>$json->serialno, "txnAmt"=> $json->txnAmt, "currencyCode"=>$json->currency ];
								$purchaseContent = $this->getPurchaseContent();
								$combined = array_merge($purchaseContent,$customerData);
								array_push($requiredFlds,'channelType','backUrl','origQryId');
							}
							else{
								throw new \Exception("Error, contact system administrator");

							}
							break;
						case self::COMPLETEPREAUTH:

							$txntype="03";
							$txnSubType="00";
							$requiredUserData = ["txnAmt","txnTime","orderId","serialno","currency"];
							$isValid = $this->validateRequest($json,$requiredUserData);
							if($isValid){

								$customerData = ["origQryId"=>$json->serialno, "txnAmt"=> $json->txnAmt, "currencyCode"=>$json->currency];
								$purchaseContent = $this->getPurchaseContent();
								$combined = array_merge($purchaseContent,$customerData);
								array_push($requiredFlds,'txnAmt','channelType','currencyCode','backUrl','origQryId');
							}
							else{
								throw new \Exception("Error, contact system administrator");
							
							}

							break;

						case self::CANCELCOMPLETEPREAUTH:
							//PreAuth Complete Cancel
							//$url = $this->backTransUrl;

							$txntype="33";
							$txnSubType="00";

							$customerData = ["origQryId"=>$json->serialno, "txnAmt"=> $json->txnAmt];
							$purchaseContent = $this->getPurchaseContent();
							$combined = array_merge($purchaseContent,$customerData);
							array_push($requiredFlds,'txnAmt','channelType','currencyCode','backUrl','origQryId');

							break;

						case self::RECURRING:
							//$url = $this->backTransUrl;

							$txntype="11";
							$txnSubType="01";

							//Recurring
							break;
						case self::QUERY:
							//query
							$txntype="00";
							$txnSubType="00";
							$requiredUserData = ["txnTime","orderId"];
							$isValid = $this->validateRequest($json,$requiredUserData);
							if($isValid){
							
							
								//$custInfo = new CustomerInfo($txntype, $txnSubType);
								$url = self::SINGLEQUERYURL;

								$combined = ["certType"=>"01"];
								array_push($requiredFlds,'certType');
							}
							else{
								throw new \Exception("Error, contact system administrator");

							}
							break;

						default:
							new \Exception ("invalid type");

					}
					$defaultContent = $this->getDefaultContent();
					//print_r($defaultContent);


					$defaultContent=array_merge($defaultContent,(array)$combined);

					//$merged = $classobj->mergeData($defaultContent, $json, $type = null);
					$types = ["txnType"=>$txntype,"txnSubType"=>$txnSubType];
					$userData = ["orderId"=>$json->orderId,"txnTime"=>$json->txnTime];
					$merged = array_merge($defaultContent, $userData,$types);

					//$merged = $this->mergeData($defaultContent, $userData, $types);
					$sort = ksort($merged);
					//var_dump($merged);
					//$signature = $classobj->processRequest($merged, $requiredFlds);
					$signature = $this->processRequest($merged, $requiredFlds);
					//echo "signature: ". $signature. "\n";


					//$certID = $upopconf->certid;
					//$certDetail = ["signature"=>$signature,"certId"=>$certID];
					$certDetail = ["signature"=>$signature];
					$merged_final= array_merge($merged,$certDetail);

					// $sorted = ksort($merged_final);
					//var_dump($merged_final);
					$port = $this->port;
					//$data = $classobj->initiateRequest($merged_final,$url,$port);
					$data = $this->initiateRequest($merged_final,$url,$port);
					
					if(strlen($data) < 1 || strtoupper($data)==="INVALID REQUEST."){
						$this->log->error( $data . " Request URL is missing");

						throw new \Exception('Error, contact system administrator');
					}
					$ares = explode("&",$data);
					//Svar_dump($ares);
					//$resp="";

					foreach( $ares as $item){

						$temp = explode("=",$item); //accNo will lose the == and this should be returned
						$key=$temp[0];
						//var_dump($temp);
						if($key==='accNo')
							$value=$temp[1]."=="; //return these == lost during explode
						else
							$value=$temp[1];

						$resp[$key] =  $value;

					}


					foreach($resp as $key => $value ){
					   if (  $key==='signPubKeyCert'){
						   $pubcertStr=$value;
						   break;
					   }
					}
					$respCode = $resp['respCode'] ;
					//print_r($resp);
					$validCert = $this->isPubKeyCertValid($pubcertStr);
					if ($validCert){

						if ($respCode =='00'){
							$validData = $this->isDataValid($resp);

							if ($validData){
								$queryId= $resp['queryId']	;

								echo '{
									"status":"200",
									"description":"OK",
									"queryId":"'.$queryId.'",
									"respCode":"'.$respCode.'"

								}';
							}
							else{
								echo '{
										"status":"400",
										"description":"Error, contact system administrator",
										"respCode":"'."99".'"

									}';
							}

						}
						else{
							echo '{
								"status":"400",
								"description":"failed",
								"respCode":"'.$respCode.'"

							}';
						}
					}	
					else{
						die("certificate not valid");
					}

				}
				else{
					echo '{
						"status":"400",
						"description":"Missing required Field. Please ensure card details and/or sms code is provided";

					}';

				}

			}
			else{

				new \Exception ("invalid JSON request");

			}
		}
		catch(\Exception $e){
					echo '{
					"status":"400",
					"description":"'. $e->getMessage().
				'"
				}';
		}
	}
	
}

?>